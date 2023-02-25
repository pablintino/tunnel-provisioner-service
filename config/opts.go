package config

import (
	"github.com/jessevdk/go-flags"
)

type RunningOpts struct {
	ConfigPath string `short:"f" long:"file" description:"Configuration file path" required:"true" env:"TPS_CONFIG_FILE"`
	Verbose    bool   `short:"v" long:"verbose" description:"Show verbose debug information" env:"TPS_DEBUG"`
}

func ParseRunningOpts() (*RunningOpts, error) {
	opts := &RunningOpts{}
	_, err := flags.Parse(opts)
	return opts, err
}
