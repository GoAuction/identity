package config

import (
	"fmt"
	"strings"

	"github.com/spf13/viper"
)

type AppConfig struct {
	Port             string `mapstructure:"port" yaml:"port"`
	PostgresUsername string `mapstructure:"postgres_username" yaml:"postgres_username"`
	PostgresPassword string `mapstructure:"postgres_password" yaml:"postgres_password"`
	PostgresDatabase string `mapstructure:"postgres_database" yaml:"postgres_database"`
	PostgresSSLMode  string `mapstructure:"postgres_sslmode" yaml:"postgres_sslmode"`
	PostgresHost     string `mapstructure:"postgres_host" yaml:"postgres_host"`
	PostgresPort     string `mapstructure:"postgres_port" yaml:"postgres_port"`
	JWTSecret        string `mapstructure:"jwt_secret" yaml:"jwt_secret"`
}

func Read() *AppConfig {
	viper.SetConfigName("config")      // name of config file (without extension)
	viper.SetConfigType("yaml")        // REQUIRED if the config file does not have the extension in the name
	viper.AddConfigPath("$PWD/config") // call multiple times to add many search paths
	viper.AddConfigPath(".")           // optionally look for config in the working directory
	viper.AddConfigPath("/config")     // optionally look for config in the working directory
	viper.AddConfigPath("./config")    // optionally look for config in the working directory
	configureEnvOverrides()
	err := viper.ReadInConfig() // Find and read the config file
	if err != nil {             // Handle errors reading the config file
		panic(fmt.Errorf("fatal error config file: %w", err))
	}

	var appConfig AppConfig
	err = viper.Unmarshal(&appConfig)
	if err != nil {
		panic(fmt.Errorf("fatal error unmarshalling config: %w", err))
	}

	return &appConfig
}

func configureEnvOverrides() {
	viper.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))
	viper.AutomaticEnv()

	keys := []string{
		"port",
		"postgres_username",
		"postgres_password",
		"postgres_database",
		"postgres_sslmode",
		"postgres_host",
		"postgres_port",
		"jwt_secret",
	}

	for _, key := range keys {
		if err := viper.BindEnv(key); err != nil {
			panic(fmt.Errorf("fatal error binding env for %s: %w", key, err))
		}
	}
}
