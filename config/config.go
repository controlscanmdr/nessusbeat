// Config is put into a different package to prevent cyclic imports in case
// it is needed in several locations

package config

type Config struct {
	CACertPath      string `config:"cacert_path"`
	ReportPath      string `config:"report_path"`
	APIUrl          string `config:"api_url"`
	APIUsername     string `config:"api_username"`
	APIPassword     string `config:"api_password"`
	TimestampFields string `config:"timestamp_fields"`
}

var DefaultConfig = Config{
	ReportPath: "/opt/nessus/var/nessus/users/admin/reports",
	APIUrl:     "https://localhost:8834",
}
