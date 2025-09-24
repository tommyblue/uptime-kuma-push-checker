package main

import (
	"flag"
	"log"
	"os"

	push_checker "github.com/tommyblue/uptime-kuma-push-checker"
	"gopkg.in/yaml.v2"
)

var (
	confFlag = flag.String("config", "", "Path to the config file")
	helpFlag = flag.Bool("help", false, "Show help and exit")
)

func main() {
	flag.Parse()

	if *helpFlag {
		flag.PrintDefaults()
		os.Exit(0)
	}

	if *confFlag == "" {
		log.Fatalf("Config file path is required")
	}

	f, err := os.ReadFile(*confFlag)
	if err != nil {
		log.Fatalf("Cannot read config file: %v", err)
	}

	conf := &push_checker.Config{}
	err = yaml.Unmarshal(f, conf)
	if err != nil {
		log.Fatalf("Unmarshal: %v", err)
	}

	checker, err := push_checker.New(conf)
	if err != nil {
		log.Fatalf("Cannot setup Push Checker: %v", err)
	}

	if err := checker.Run(); err != nil {
		log.Fatalf("Run error: %v", err)
	}
}
