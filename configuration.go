package main

import (
	"encoding/json"
	"io/ioutil"
)

type Configuration struct {
	Server       string
	Port         string
	Key          string
	Cert         string
	Ssl          bool
	Ext          string
	MailFolder   string `json:"mail_folder"`
	StaticFolder string `json:"static_folder"`
}

func getConfiguration(file string) (Configuration, error) {
	var configuration Configuration
	buffer, err := ioutil.ReadFile(file)
	if err != nil {
		return Configuration{}, err
	}
	err = json.Unmarshal(buffer, &configuration)
	return configuration, err
}
