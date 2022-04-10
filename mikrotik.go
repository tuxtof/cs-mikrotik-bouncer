package main

import (
	"fmt"
	"strings"

	"github.com/crowdsecurity/crowdsec/pkg/models"
	"github.com/rs/zerolog/log"

	"github.com/go-routeros/routeros"
)

func dial() (*routeros.Client, error) {
	if useTLS {
		return routeros.DialTLS(mikrotikHost, username, password, nil)
	}
	return routeros.Dial(mikrotikHost, username, password)
}

func (mal *mikrotikAddrList) initMikrotik() {

	log.Info().Msg("Connecting to mikrotik")

	c, err := dial()
	if err != nil {
		log.Fatal().Err(err).Str("host", mikrotikHost).Str("username", username).Bool("useTLS", useTLS).Msg("Connection failed")
	}

	if async {
		c.Async()
	}

	mal.c = c

	mal.cache = make(map[string]string)

	log.Print("mikrotik list addr")
	initCmd := "/ip/firewall/address-list/print ?list=crowdsec =.proplist=.id,address"
	r, err := c.RunArgs(strings.Split(initCmd, " "))
	if err != nil {
		log.Fatal().Err(err).Msg("address-list print failed")
	}
	log.Info().Msgf("fill %d entry in internal addrList\n", len(r.Re))
	for _, v := range r.Re {
		mal.cache[v.Map["address"]] = v.Map[".id"]
	}

}

func (mal *mikrotikAddrList) decisionProcess(streamDecision *models.DecisionsStreamResponse) {

	for _, decision := range streamDecision.Deleted {
		log.Info().Msgf("removed decisions: IP: %s | Scenario: %s | Duration: %s | Scope : %v", *decision.Value, *decision.Scenario, *decision.Duration, *decision.Scope)

		if mal.cache[*decision.Value] != "" {
			log.Info().Msgf("Verify address %s in mikrotik", *decision.Value)
			checkCmd := fmt.Sprintf("/ip/firewall/address-list/print =.proplist=address ?.id=%s", mal.cache[*decision.Value])
			r, err := mal.c.RunArgs(strings.Split(checkCmd, " "))
			if err != nil {
				log.Fatal().Err(err).Msg("address-list search cmd failed")
			}

			if len(r.Re) == 1 && r.Re[0].Map["address"] == *decision.Value {
				delCmd := fmt.Sprintf("/ip/firewall/address-list/remove =numbers=%s", mal.cache[*decision.Value])
				_, err = mal.c.RunArgs(strings.Split(delCmd, " "))
				if err != nil {
					log.Error().Err(err).Msg("address-list remove cmd failed")
				}
				log.Info().Msgf("%s removed from mikrotik", *decision.Value)
			} else {
				log.Info().Msgf("%s already removed from mikrotik", *decision.Value)
			}
			delete(mal.cache, *decision.Value)

		} else {
			log.Info().Msgf("%s not find in local cache", *decision.Value)
		}

	}
	for _, decision := range streamDecision.New {
		log.Info().Msgf("new decisions from %s: IP: %s | Scenario: %s | Duration: %s | Scope : %v", *decision.Origin, *decision.Value, *decision.Scenario, *decision.Duration, *decision.Scope)

		addCmd := fmt.Sprintf("/ip/firewall/address-list/add#=list=crowdsec#=address=%s#=comment=%s#=timeout=%s", *decision.Value, *decision.Scenario, *decision.Duration)

		if mal.cache[*decision.Value] != "" {
			log.Info().Msgf("Address %s already present", *decision.Value)
		} else {
			r, err := mal.c.RunArgs(strings.Split(addCmd, "#"))
			if err != nil {
				log.Error().Err(err).Msg("address-list add cmd failed")
			} else {
				mal.cache[*decision.Value] = r.Done.List[0].Value
				log.Info().Msgf("Address %s blocked in mikrotik", *decision.Value)
			}
		}
	}
}
