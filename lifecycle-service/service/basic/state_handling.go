// Licensed Materials – Property of IBM.
// © Copyright IBM Corp. 2017

package basic

import (
	"errors"
	"net/http"
	"strconv"
	"time"

	"context"

	dbDef "github.ibm.com/Alchemy-Key-Protect/go-db-service/services/metadata/service/definitions"
	"github.ibm.com/Alchemy-Key-Protect/key-management-core/lifecycle-service/definitions"
	"github.ibm.com/Alchemy-Key-Protect/kp-go-models/communications"
	"github.ibm.com/Alchemy-Key-Protect/kp-go-models/secrets"

	"sync"
)

const timeFormat = "2006-01-02 15:04:05 -0700 MST"

/* Helper functions for state handling
 */
func getReason(state secrets.KeyStates) secrets.NonactiveReasons {
	var reason secrets.NonactiveReasons
	if state == secrets.Activation {
		reason = secrets.KeyActive
	} else if state == secrets.Deactivated {
		reason = secrets.Expired
	} else if state == secrets.Destroyed {
		reason = secrets.GenerationFailed
	}
	return reason
}

func filterErroredKeys(metadataArr []*secrets.Secret) []*secrets.Secret {
	var filteredMetadata []*secrets.Secret
	for _, secret := range metadataArr {
		if secret.State != secrets.Destroyed {
			filteredMetadata = append(filteredMetadata, secret)
		}
	}
	return filteredMetadata
}

func getInactiveKeys(metadataArr []*secrets.Secret) []*secrets.Secret {
	var inactives []*secrets.Secret
	for _, secret := range metadataArr {
		if secret == nil {
			continue
		}
		if secret.State == secrets.Preactivation {
			inactives = append(inactives, secret)
		}
	}
	return inactives
}

func checkStatus(inactives []*secrets.Secret, client dbDef.Service, updateRequest *communications.UpdateRequest, strategy definitions.Keystore) {
	if len(inactives) == 0 {
		return
	}
	wg := sync.WaitGroup{}
	wg.Add(len(inactives))
	for _, inactiveSecret := range inactives {
		state, err := strategy.CheckSecret(inactiveSecret.ID)
		if err == nil {
			// Check for generation error
			if state == secrets.Destroyed {
				handleFailedGeneration(inactiveSecret.ID, inactiveSecret, client, updateRequest)
			} else if state != inactiveSecret.State {
				updates := map[string]string{"state": strconv.Itoa(int(state)), "nonactive_state_reason": strconv.Itoa(int(secrets.KeyActive))}
				updateRequest.SetUpdates(updates)
				updateRequest.SetID(inactiveSecret.ID)

				client.Update(context.Background(), updateRequest)
				inactiveSecret.SetState(state)
			}
		}
		wg.Done()
	}
	wg.Wait()
}

//Returns if the secret is active secretsd on the secret's activation date.
func handleActivationTime(metadata *secrets.Secret) (bool, error) {
	if len(metadata.ActivationDate) == 0 {
		return true, nil
	}

	activeTime, err := time.Parse(time.RFC3339, metadata.ActivationDate)
	if err != nil {
		return false, err
	}
	now := time.Now()
	if now.After(activeTime) {
		return true, nil
	}
	return false, nil
}

//Returns if the secret is expired according to the secret's expiration date
func handleExpirationTime(metadata *secrets.Secret) (bool, error) {
	if len(metadata.ExpirationDate) == 0 {
		return false, nil
	}

	// only return secretMaterial when secret not expired
	// if it's expired, clear payload and set state to Deactivated.  Currently, no state transitions are really enforced, so a delete will delete deactivated secrets
	// once we support more states
	expiration, parseErr := time.Parse(time.RFC3339, metadata.ExpirationDate)
	if parseErr != nil {
		return true, errors.New(http.StatusText(http.StatusInternalServerError) + ": Invalid expiration date: " + metadata.ExpirationDate)
	}

	if time.Now().After(expiration) == true {
		return true, nil
	}
	return false, nil
}

func handleFailedGeneration(id string, metadata *secrets.Secret, client dbDef.Service, updateRequest *communications.UpdateRequest) error {
	metadata.SetState(secrets.Destroyed)
	metadata.NonactiveReason = secrets.GenerationFailed

	idRequest := communications.NewIDRequest()
	idRequest.SetHeaders(updateRequest.Headers)
	idRequest.SetID(updateRequest.ID)

	_, err := client.Delete(context.Background(), idRequest)
	if err != nil {
		return err
	}

	updates := map[string]string{"state": strconv.Itoa(int(secrets.Destroyed)), "nonactive_state_reason": strconv.Itoa(int(secrets.GenerationFailed))}
	updateRequest.SetUpdates(updates)
	_, err = client.Update(context.Background(), updateRequest)
	if err != nil {
		return err
	}

	return nil
}

// repairDestroyedSecretThatExpired repairs the database where we introduced a bug in PROD on 12/12/2016 where Destroyed secrets that are expired get overwritten as Deactivated state instead of
// left in the Destroyed state.  Do this before checking expiration, since we fixed the expiration function to no longer overwrite state in this case.
// Eventually, this repair function can be removed.
func repairDestroyedSecretThatExpired(metadata *secrets.Secret, client dbDef.Service, updateRequest *communications.UpdateRequest) error {
	if metadata.Deleted == true && metadata.State == secrets.Deactivated {

		//TODO ARS constants in this file instead of "state" & "nonactive_state_reason"
		updates := map[string]string{"state": strconv.Itoa(int(secrets.Destroyed)), "nonactive_state_reason": strconv.Itoa(int(metadata.NonactiveReason))}
		updateRequest.SetUpdates(updates)
		_, updateErr := client.Update(context.Background(), updateRequest)
		//updateErr := dbService.UpdateSecretState(metadata.ID, models.Destroyed, metadata.NonactiveReason)
		if updateErr != nil {
			return updateErr
		}
	}
	return nil
}

func handleStateChange(metadata *secrets.Secret, updateSecret bool, client dbDef.Service, updateRequest *communications.UpdateRequest) error {
	//Should only be called on secrets that have a secret ref in barbican
	oldState := metadata.State
	active, err := handleActivationTime(metadata)
	if err != nil {
		return err
	}

	if repairErr := repairDestroyedSecretThatExpired(metadata, client, updateRequest); repairErr != nil {
		return repairErr
	}

	// Accoriding to NIST 800-57 Part4 rev4 Chapter 7, the only states where expiration state change to deactivate are meaningful are:
	//   - models.Activation
	//   - models.Suspended
	var expired bool
	if metadata.State == secrets.Activation || metadata.State == secrets.Suspended {
		expired, err = handleExpirationTime(metadata)
		if err != nil {
			return err
		}
	}

	if metadata.State != secrets.Destroyed {
		adjustSecretState(metadata, expired, active)
	}

	if metadata.State != oldState && updateSecret {
		updates := map[string]string{"state": strconv.Itoa(int(metadata.State)), "nonactive_state_reason": strconv.Itoa(int(metadata.NonactiveReason))}
		updateRequest.SetUpdates(updates)
		_, err := client.Update(context.Background(), updateRequest)
		if err != nil {
			return err
		}
	}

	return nil
}

func handleStateChangeForRange(metadataArr []*secrets.Secret, client dbDef.Service,
	updateRequest *communications.UpdateRequest, strategy definitions.Keystore) error {
	for _, metadata := range metadataArr {
		activeInBarbican := true
		oldState := metadata.State
		if metadata.State == secrets.Preactivation {
			barbicanState, err := strategy.CheckSecret(metadata.ID)
			if err != nil {
				return err
			}
			if barbicanState == secrets.Preactivation {
				activeInBarbican = false
			} else if barbicanState == secrets.Destroyed {
				activeInBarbican = false

				//TODO ARS:  Should we be returning the error from here?
				handleFailedGeneration(metadata.ID, metadata, client, updateRequest)
			}
		}

		if activeInBarbican {
			active, err := handleActivationTime(metadata)
			if err != nil {
				return err
			}

			if repairErr := repairDestroyedSecretThatExpired(metadata, client, updateRequest); repairErr != nil {
				return repairErr
			}

			// Accoriding to NIST 800-57 Part4 rev4 Chapter 7, the only states where expiration state change to deactivate are meaningful are:
			//   - models.Activation
			//   - models.Suspended
			// Therefore for any other state, don't do anything.
			// Using DeMorgan's transformation of !(Activation + Suspended) = !Actvication * !Suspended
			var expired bool
			if metadata.State == secrets.Activation || metadata.State == secrets.Suspended {
				expired, err = handleExpirationTime(metadata)
				if err != nil {
					return err
				}
			}

			if metadata.State != secrets.Destroyed {
				adjustSecretState(metadata, expired, active)
			}
		}
		if metadata.State != oldState {
			updateRequest.SetID(metadata.ID)
			updates := map[string]string{"state": strconv.Itoa(int(metadata.State)), "nonactive_state_reason": strconv.Itoa(int(metadata.NonactiveReason))}
			updateRequest.SetUpdates(updates)
			_, err := client.Update(context.Background(), updateRequest)
			if err != nil {
				return err
			}
		}
	} //End for
	return nil
}

func adjustSecretState(metadata *secrets.Secret, expired, active bool) {
	if expired {
		//expired
		metadata.SetState(secrets.Deactivated)
		metadata.NonactiveReason = secrets.Expired
	} else if active {
		//active
		metadata.SetState(secrets.Activation)
		metadata.NonactiveReason = secrets.KeyActive
	} else {
		//preactive
		metadata.SetState(secrets.Preactivation)
	}
}
