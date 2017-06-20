// © Copyright 2016 IBM Corp. Licensed Materials – Property of IBM.

package cmd

import (
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"runtime"
	"strings"
	"syscall"

	"github.ibm.com/Alchemy-Key-Protect/key-management-core/lifecycle-service/definitions"
	"github.ibm.com/Alchemy-Key-Protect/key-management-core/lifecycle-service/service"
	"github.ibm.com/Alchemy-Key-Protect/key-management-core/lifecycle-service/transport"
	"github.ibm.com/Alchemy-Key-Protect/key-management-core/utils/logging"
	"github.ibm.com/Alchemy-Key-Protect/kp-go-config"
	"github.ibm.com/Alchemy-Key-Protect/kp-go-consts"

	"github.com/go-kit/kit/log"
	stdopentracing "github.com/opentracing/opentracing-go"
	zipkin "github.com/openzipkin/zipkin-go-opentracing"
	"github.com/spf13/cobra"
)

var (
	config configuration.Configuration

	// mainSemver is set by build to denote the semver numbering
	mainSemver string

	// mainCommit is set by the build to denote the commit SHA1 of the build
	mainCommit string

	hostname string

	deployed = (runtime.GOOS == constants.LinuxRuntime)

	// Zipkin/tracing variables
	serviceAddr, zipkinAddr, zipkinKafkaAddr string
	tracer                                   stdopentracing.Tracer
	collector                                zipkin.Collector
)

func init() {
	// Set config
	config = configuration.Get()

	// get hostname
	var err error
	hostname, err = os.Hostname()
	if err != nil {
		panic(err)
	}

	serviceAddr = fmt.Sprintf("%s:%d", config.GetString("host.ipv4_address"), config.GetInt("host.port"))
	zipkinAddr = config.GetString("tracer.zipkin.httpEndpoint")
	zipkinKafkaAddr = config.GetString("tracer.zipkinKafka.host")
}

func isDeployed() bool {
	return deployed
}

// getEnvFromHostname maps environment based on the deployment hostname.  If not deployed, default to development
func getEnvFromHostname() (env string) {
	// Ansible declares hostnames by <env>-<datacenter>-keyprotect-<machinerole>-<instance>-<domain>
	envPortion := strings.Split(hostname, "-")[0]
	converstionTable := map[string]string{
		"dev":      constants.DevelopmentEnvironment,
		"prestage": constants.PrestagingEnvironment,
		"stage":    constants.StagingEnvironment,
		"prod":     constants.ProductionEnvironment,
	}
	env = converstionTable[envPortion]
	if env == "" {
		env = constants.DevelopmentEnvironment
	}
	return
}

// getRegionFromHostname maps bluemix region based on the deployment hostname.  If not deployed, default to dallas
func getRegionFromHostname() (region string) {
	// Ansible declares hostnames by <env>-<datacenter>-keyprotect-<machinerole>-<instance>-<domain>
	//TODO: https://github.ibm.com/Alchemy-Key-Protect/key-protect-backlog/issues/395
	//TODO: https://github.ibm.com/Alchemy-Key-Protect/key-protect-backlog/issues/396
	chunks := strings.Split(hostname, "-")
	if len(chunks) < 2 {
		region = constants.DallasRegion
		return
	}
	dataCenterPortion := chunks[1]
	converstionTable := map[string]string{
		"dal09": constants.DallasRegion,
		"mon01": constants.DallasRegion,
		"lon02": constants.LondonRegion,
		"syd01": constants.SydneyRegion,
	}
	region = converstionTable[dataCenterPortion]
	return
}

func validateVersion(config configuration.Configuration) {
	// ensure that the configuration file and binary file were built together
	configVersion := config.GetString("version.semver")
	if isDeployed() && mainSemver != configVersion {
		panic(fmt.Sprintf("Version mismatch enabled on %s: expected %s have %s ", runtime.GOOS, configVersion, mainSemver))
	}

	configCommit := config.GetString("version.commit")
	if isDeployed() && mainCommit != mainCommit {
		panic(fmt.Sprintf("Commit mismatch enabled on %s: expected %s have %s ", runtime.GOOS, configCommit, mainCommit))
	}
}

func setAnalyticsService(keyService definitions.Service) definitions.Service {
	// only add analytics middleware if deployed to a real environment
	if isDeployed() != true {
		return keyService
	}

	environment := getEnvFromHostname()
	region := getRegionFromHostname()

	var proxy string
	switch environment {
	case constants.DevelopmentEnvironment:
		proxy = config.GetString(constants.DevProxy)
	case constants.PrestagingEnvironment:
		proxy = config.GetString(constants.PrestagingProxy)
	case constants.StagingEnvironment:
		proxy = config.GetString(constants.StagingProxy)
	case constants.ProductionEnvironment:
		proxy = config.GetString(constants.ProductionProxy)
	}
	return service.NewAnalyticsService(
		environment,
		region,
		proxy,
		keyService,
	)
}

func getTracerAndCollector(logger log.Logger) (stdopentracing.Tracer, zipkin.Collector, error) {
	var err error
	if zipkinAddr != "" {
		logger.Log("zipkinAddr", zipkinAddr) // #nosec
		collector, err = zipkin.NewHTTPCollector(zipkinAddr)
		if err != nil {
			return nil, nil, err
		}
	} else {
		tracer = stdopentracing.GlobalTracer() // no-op
		collector = zipkin.NopCollector{}      // no-op
	}

	tracer, err = zipkin.NewTracer(zipkin.NewRecorder(collector, false, serviceAddr, config.GetString("service.name.code")))
	if err != nil {
		return nil, nil, err
	}

	return tracer, collector, nil
}

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use:   "key-management-core",
	Short: "IBM Key Protect Core service",
	Long:  `IBM Key Protect Core service provides access to all the microservices`,
	// Uncomment the following line if your bare application
	// has an action associated with it:
	Run: func(cmd *cobra.Command, args []string) {
		logger := logging.GlobalLogger()

		validateVersion(config)

		rootLogger := log.With(logger, "component", "root")
		rootLogger.Log("semver", mainSemver, "commit", mainCommit)

		tracer, collector, err := getTracerAndCollector(rootLogger)
		if err != nil {
			rootLogger.Log("err", err)
			panic("cannot build tracer and collector")
		}
		defer collector.Close()

		errc := make(chan error, 2)

		keyService := service.NewBasicService()
		keyService = service.NewLoggingService(log.With(logger, "component", "secrets", "caller", log.DefaultCaller), keyService)
		keyService = setAnalyticsService(keyService)
		keyService = service.NewInstrumentingService(keyService)

		httpLogger := log.With(logger, "transport", "http")

		mux := http.NewServeMux()

		// Note: need trailing slash for endpoint routing
		mux.Handle("/api/v2/", transport.MakeHandlerV2(keyService, tracer, httpLogger))
		http.Handle("/", mux) //This will go away if we go back to https

		// TODO: this function will need to be replaced with what is in `key-management-api` once we enable TLS between microservices.
		go func() {
			if errLog := logger.Log("transport", "http", "address", ":"+config.GetString(constants.HostPort), "msg", "listening"); errLog != nil {
				panic("cannot log basic server info")
			}
			errc <- http.ListenAndServe(":"+config.GetString(constants.HostPort), nil)
		}()

		go func() {
			signalChan := make(chan os.Signal)
			signal.Notify(signalChan, syscall.SIGINT)
			errc <- fmt.Errorf("%s", <-signalChan)
		}()

		errSigLog := logger.Log("terminated", <-errc)
		if errSigLog != nil {
			panic("cannot log basic server info")
		}

	},
}

// SetVersion needs to be called by main.main() to set build version, so that the version commmand returns the value matching the build
func SetVersion(version string, commit string) {
	if version == "" {
		mainSemver = "0.0.0"
	} else {
		mainSemver = version
	}
	if commit == "" {
		mainCommit = "0000"
	} else {
		mainCommit = commit
	}
}

// Execute adds all child commands to the root command sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(-1)
	}
}
