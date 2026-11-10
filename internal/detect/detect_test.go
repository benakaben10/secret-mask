package detect

import (
	"context"
	"encoding/json"
	"errors"
	"maps"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"
)

// Secrets are assembled at run time so this source file never contains a detectable secret.
var (
	awsKey      = "AKIA" + "QYLPMN5HHHFPZAM2"
	githubToken = "ghp_" + "8Rk2Lm9Qx7Vt3Zb5Nc1Hd4Jf6Gs0Pw2Ya8Ue"
)

func tree(t *testing.T, files map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	for rel, content := range files {
		p := filepath.Join(dir, filepath.FromSlash(rel))
		os.MkdirAll(filepath.Dir(p), 0o755)
		if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

func secrets(fs []Finding) []string {
	var out []string
	for _, f := range fs {
		out = append(out, f.File+"="+f.Secret)
	}
	slices.Sort(out)
	return out
}

func TestScanDefaultRules(t *testing.T) {
	dir := tree(t, map[string]string{
		"config/.env": "AWS_ACCESS_KEY_ID=" + awsKey + "\n",
		"ci/build.sh": "export GITHUB_TOKEN=" + githubToken + "\n",
		"README.md":   "nothing to see\n",
	})
	got, err := Scan(context.Background(), Options{Root: dir})
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"ci/build.sh=" + githubToken, "config/.env=" + awsKey}
	if !reflect.DeepEqual(secrets(got), want) {
		t.Errorf("Scan = %v, want %v", secrets(got), want)
	}
	for _, f := range got {
		if f.RuleID == "" || f.StartLine != 1 {
			t.Errorf("finding %+v lacks rule/line", f)
		}
	}
}

func TestScanSingleFileAndSubdir(t *testing.T) {
	dir := tree(t, map[string]string{
		"a/.env": "AWS_ACCESS_KEY_ID=" + awsKey + "\n",
		"b/.env": "GITHUB_TOKEN=" + githubToken + "\n",
	})
	got, err := Scan(context.Background(), Options{Root: dir, Target: "b/.env"})
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(secrets(got), []string{"b/.env=" + githubToken}) {
		t.Errorf("file scan = %v", secrets(got))
	}
	got, err = Scan(context.Background(), Options{Root: dir, Target: "a"})
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(secrets(got), []string{"a/.env=" + awsKey}) {
		t.Errorf("subdir scan = %v", secrets(got))
	}
}

func TestScanRelativeRootFromOtherCwd(t *testing.T) {
	parent := t.TempDir()
	dir := filepath.Join(parent, "proj")
	os.MkdirAll(dir, 0o755)
	os.WriteFile(filepath.Join(dir, ".env"), []byte("KEY="+awsKey+"\n"), 0o644)
	t.Chdir(parent)
	got, err := Scan(context.Background(), Options{Root: "proj"})
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(secrets(got), []string{".env=" + awsKey}) {
		t.Errorf("Scan = %v", secrets(got))
	}
}

const extraRule = `
[extend]
useDefault = true

[[rules]]
id = "custom-ticket"
regex = '''TICKET=(TK-\d{6,})'''
secretGroup = 1
keywords = ["ticket"]
`

func TestScanRepoConfigAndIgnore(t *testing.T) {
	dir := tree(t, map[string]string{
		".gitleaks.toml": extraRule,
		".env":           "TICKET=TK-123456\nAWS_ACCESS_KEY_ID=" + awsKey + "\n",
	})
	got, err := Scan(context.Background(), Options{Root: dir})
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(secrets(got), []string{".env=" + awsKey, ".env=TK-123456"}) {
		t.Fatalf("repo config not used: %v", secrets(got))
	}

	// .gitleaksignore (file:rule:line) suppresses one finding.
	var awsRule string
	for _, f := range got {
		if f.Secret == awsKey {
			awsRule = f.RuleID
		}
	}
	os.WriteFile(filepath.Join(dir, ".gitleaksignore"), []byte(".env:"+awsRule+":2\n"), 0o644)
	got, err = Scan(context.Background(), Options{Root: dir})
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(secrets(got), []string{".env=TK-123456"}) {
		t.Errorf("with .gitleaksignore: %v", secrets(got))
	}
}

func TestScanConfigPrecedence(t *testing.T) {
	dir := tree(t, map[string]string{".env": "TICKET=TK-123456\n"})
	cfg := filepath.Join(t.TempDir(), "leak.toml")
	os.WriteFile(cfg, []byte(extraRule), 0o644)

	got, _ := Scan(context.Background(), Options{Root: dir})
	if len(got) != 0 {
		t.Errorf("default rules should not know the custom format: %v", secrets(got))
	}
	got, err := Scan(context.Background(), Options{Root: dir, Config: cfg})
	if err != nil || len(got) != 1 {
		t.Errorf("explicit config: %v, %v", secrets(got), err)
	}
	t.Setenv("GITLEAKS_CONFIG", cfg)
	got, err = Scan(context.Background(), Options{Root: dir})
	if err != nil || len(got) != 1 {
		t.Errorf("GITLEAKS_CONFIG: %v, %v", secrets(got), err)
	}
}

func TestScanErrors(t *testing.T) {
	dir := t.TempDir()
	if _, err := Scan(context.Background(), Options{Root: dir, Target: "missing"}); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("missing target: %v", err)
	}
	if _, err := Scan(context.Background(), Options{Root: dir, Config: filepath.Join(dir, "nope.toml")}); err == nil {
		t.Error("missing config: want an error")
	}
	bad := filepath.Join(dir, "bad.toml")
	os.WriteFile(bad, []byte("[[rules]]\nid = \"x\"\nregex = '''(unclosed'''\n"), 0o644)
	if _, err := Scan(context.Background(), Options{Root: dir, Config: bad}); err == nil {
		t.Error("invalid config: want an error")
	}
}

func TestLoadConfigDefault(t *testing.T) {
	cfg, err := LoadConfig("")
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.Rules) < 100 {
		t.Errorf("built-in config has %d rules", len(cfg.Rules))
	}
}

func writeReport(t *testing.T, findings []map[string]any) string {
	t.Helper()
	data, _ := json.Marshal(findings)
	path := filepath.Join(t.TempDir(), "report.json")
	os.WriteFile(path, data, 0o600)
	return path
}

func TestLoadReport(t *testing.T) {
	dir := t.TempDir()
	abs, _ := filepath.Abs(dir)
	report := writeReport(t, []map[string]any{
		{"RuleID": "r1", "File": "config/.env", "StartLine": 3, "Secret": "s1"},
		{"RuleID": "r2", "File": filepath.Join(abs, "k8s", "secret.yaml"), "StartLine": 7, "Secret": "s2"},
		{"RuleID": "r3", "File": "./a/../b.json", "StartLine": 1, "Secret": "s3"},
		{"RuleID": "r4", "File": filepath.Join(filepath.Dir(abs), "outside.env"), "StartLine": 1, "Secret": "s4"},
		{"RuleID": "r5", "File": "../escape.env", "StartLine": 1, "Secret": "s5"},
	})
	got, err := LoadReport(report, dir)
	if err != nil {
		t.Fatal(err)
	}
	want := []Finding{
		{RuleID: "r1", File: "config/.env", StartLine: 3, Secret: "s1"},
		{RuleID: "r2", File: "k8s/secret.yaml", StartLine: 7, Secret: "s2"},
		{RuleID: "r3", File: "b.json", StartLine: 1, Secret: "s3"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("LoadReport =\n%+v\nwant\n%+v", got, want)
	}
}

func TestLoadReportRedacted(t *testing.T) {
	for _, secret := range []string{"REDACTED", "*****", ""} {
		report := writeReport(t, []map[string]any{{"RuleID": "r", "File": "a", "Secret": secret}})
		if _, err := LoadReport(report, t.TempDir()); !errors.Is(err, ErrRedacted) {
			t.Errorf("secret %q: err = %v, want ErrRedacted", secret, err)
		}
	}
}

func TestLoadReportErrors(t *testing.T) {
	if _, err := LoadReport(filepath.Join(t.TempDir(), "missing.json"), "."); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("missing: err = %v", err)
	}
	bad := filepath.Join(t.TempDir(), "bad.json")
	os.WriteFile(bad, []byte("not json"), 0o600)
	if _, err := LoadReport(bad, "."); err == nil || !strings.Contains(err.Error(), "parse gitleaks report") {
		t.Errorf("bad json: err = %v", err)
	}
}

func TestBuiltinPasswordRules(t *testing.T) {
	caught := map[string]string{
		".env":                      "DB_PASSWORD=Admin@123\n",
		".env.example":              "export PGPASSWORD=hunter22\n",
		"config/app.yaml":           "db:\n  password: P@ssw0rd!\n",
		"config/app.json":           `{"db": {"password": "Winter2024!"}}`,
		"src/settings.py":           `DATABASE_PASSWORD = 'S3cret-Pass'`,
		"src/main.go":               "conn := Connect(\"postgres://app:Dbpass-77@db:5432/app\")\n",
		"appsettings.json":          `{"Db": "Server=sql1;User Id=sa;Password=Sql@dmin1;"}`,
		"conf/server.xml":           "<db.password>XmlPass99</db.password>\n",
		"deploy/run.sh":             "mysql --password='Mysql#2024' app\n",
		"settings/local.properties": "spring.datasource.password=Spring!Pw1\n",
	}
	want := map[string]string{
		".env": "Admin@123", ".env.example": "hunter22", "config/app.yaml": "P@ssw0rd!", "config/app.json": "Winter2024!",
		"src/settings.py": "S3cret-Pass", "src/main.go": "Dbpass-77", "appsettings.json": "Sql@dmin1",
		"conf/server.xml": "XmlPass99", "deploy/run.sh": "Mysql#2024", "settings/local.properties": "Spring!Pw1",
	}
	got, err := Scan(context.Background(), Options{Root: tree(t, caught)})
	if err != nil {
		t.Fatal(err)
	}
	found := map[string]bool{}
	for _, f := range got {
		if want[f.File] == f.Secret {
			found[f.File] = true
		}
	}
	for file, secret := range want {
		if !found[file] {
			t.Errorf("%s: %q not found; got %v", file, secret, secrets(got))
		}
	}

	ignored := map[string]string{
		".env":             "DB_PASSWORD=${DB_PASSWORD}\nADMIN_PASSWORD=\nPGPASSWORD=$(cat /run/secret)\nPWD=/home/app\n",
		"config/app.yaml":  "password: <your-password>\npassword_hash: ''\npassword:\n  min_length: 8\n",
		"src/form.ts":      `const label = "Enter your password"; if (password === confirm) {}; const passwordInput = getPassword();`,
		"src/main.go":      "password := os.Getenv(\"DB_PASSWORD\")\nurl := \"https://example.com/path\"\n",
		"src/handler.py":   "password = request.form['password']\n",
		"templates/a.tmpl": `password: "{{ .Values.password }}"`,
		"i18n/en.json":     `{"password": "Password", "passwordHint": "At least 8 characters"}`,
	}
	got, err = Scan(context.Background(), Options{Root: tree(t, ignored)})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 0 {
		t.Errorf("placeholders and code flagged: %v", secrets(got))
	}
}

func TestBuiltinRulesCanBeDisabledOrOverridden(t *testing.T) {
	files := map[string]string{".env": "DB_PASSWORD=Admin@123\n"}
	dir := tree(t, files)
	os.WriteFile(filepath.Join(dir, ".gitleaks.toml"), []byte("[extend]\nuseDefault = true\ndisabledRules = [\"secret-mask-password-unquoted\"]\n"), 0o644)
	if got, _ := Scan(context.Background(), Options{Root: dir}); len(got) != 0 {
		t.Errorf("disabled rule still reports: %v", secrets(got))
	}
	// A rule with the same id in the project config replaces the built-in one.
	os.WriteFile(filepath.Join(dir, ".gitleaks.toml"), []byte(`[[rules]]
id = "secret-mask-password-unquoted"
regex = '''NEVER_MATCHES_(\w+)'''
`), 0o644)
	if got, _ := Scan(context.Background(), Options{Root: dir}); len(got) != 0 {
		t.Errorf("overridden rule still reports: %v", secrets(got))
	}
}

func TestPathPatternsAreRootRelative(t *testing.T) {
	// The project lives under a directory named "fixtures": an unanchored path allowlist must not hide it,
	// and an anchored one must apply.
	parent := t.TempDir()
	dir := filepath.Join(parent, "fixtures", "app")
	os.MkdirAll(filepath.Join(dir, "test"), 0o755)
	os.WriteFile(filepath.Join(dir, ".env"), []byte("AWS_ACCESS_KEY_ID="+awsKey+"\n"), 0o644)
	os.WriteFile(filepath.Join(dir, "test", "fake.env"), []byte("AWS_ACCESS_KEY_ID="+awsKey+"\n"), 0o644)
	os.WriteFile(filepath.Join(dir, ".gitleaks.toml"), []byte(`[extend]
useDefault = true
[[allowlists]]
paths = ['''^test/''', '''(?:^|/)fixtures/''']
`), 0o644)
	got, err := Scan(context.Background(), Options{Root: dir})
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(secrets(got), []string{".env=" + awsKey}) {
		t.Errorf("findings = %v", secrets(got))
	}
}

// gitleaks keeps a global [extend] depth; a long-running process (MCP server) loads configs many times.
func TestExtendDefaultSurvivesRepeatedLoads(t *testing.T) {
	dir := tree(t, map[string]string{
		".gitleaks.toml": "[extend]\nuseDefault = true\n",
		".env":           "AWS_ACCESS_KEY_ID=" + awsKey + "\n",
	})
	for i := range 5 {
		got, err := Scan(context.Background(), Options{Root: dir})
		if err != nil || len(got) != 1 {
			t.Fatalf("load %d: %v %v", i+1, secrets(got), err)
		}
	}
}

// The allowlists documented for local development (README, review_findings) must work as written.
const devAllowlists = `[extend]
useDefault = true

[[allowlists]]
description = "local dev and test files"
paths = ['''^docker-compose\.dev\.yml$''', '''^test/fixtures/''']

[[allowlists]]
description = "local dev database"
targetRules = ["secret-mask-url-password"]
regexTarget = "line"
regexes = ['''@(?:localhost|127\.0\.0\.1|db)[:/]''']

[[allowlists]]
description = "shared dev passwords"
stopwords = ["localdev"]
`

func TestDevAllowlists(t *testing.T) {
	files := map[string]string{
		".env":                   "DATABASE_URL=postgres://app:Devpass-123@localhost:5432/app\nPROD_DB_PASSWORD=Pr0d-S3cret!\nLOCAL_ADMIN_PASSWORD=localdev-admin1\nREMOTE_URL=postgres://app:Remote-Pw1@db.prod.example:5432/app\n",
		"test/fixtures/db.env":   "DB_PASSWORD=Fixture-Pass1\n",
		"docker-compose.dev.yml": "services:\n  db:\n    environment:\n      POSTGRES_PASSWORD: Compose-Pass9\n",
	}
	dir := tree(t, files)
	if got, _ := Scan(context.Background(), Options{Root: dir}); len(got) != 6 {
		t.Fatalf("without allowlists: %v", secrets(got))
	}
	os.WriteFile(filepath.Join(dir, ".gitleaks.toml"), []byte(devAllowlists), 0o644)
	got, err := Scan(context.Background(), Options{Root: dir})
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(secrets(got), []string{".env=Pr0d-S3cret!", ".env=Remote-Pw1"}) {
		t.Errorf("with dev allowlists: %v", secrets(got))
	}
}

func TestBuiltinSecretRules(t *testing.T) {
	want := map[string]string{
		".env":               "mysecret1",
		".env.local":         "abcd1234",
		"config/app.yaml":    "dev-jwt-secret",
		"src/config.ts":      "hello-key-1",
		"appsettings.json":   "3f2a9c1e-1b2c-4d5e-8f90-123456789abc",
		"src/rates.js":       "0123456789abcdef0123",
		"deploy/amqp.env":    "guest",
		"config/private.ini": "my-private-k3y",
	}
	files := map[string]string{
		".env":               "CLIENT_SECRET=mysecret1\n",
		".env.local":         "export API_KEY=abcd1234\n",
		"config/app.yaml":    "jwt:\n  secret: dev-jwt-secret\n",
		"src/config.ts":      `const apiKey = "hello-key-1";`,
		"appsettings.json":   `{"internalAuthorization": {"svc-a1b2-c3d4-client": "3f2a9c1e-1b2c-4d5e-8f90-123456789abc"}}`,
		"src/rates.js":       `fetch("https://v6.exchangerate-api.com/v6/0123456789abcdef0123/latest/USD")`,
		"deploy/amqp.env":    "BROKER_URL=amqp://guest:guest@rabbitmq:5672/\n",
		"config/private.ini": "private_key = my-private-k3y\n",
	}
	got, err := Scan(context.Background(), Options{Root: tree(t, files)})
	if err != nil {
		t.Fatal(err)
	}
	found := map[string]bool{}
	for _, f := range got {
		if want[f.File] == f.Secret {
			found[f.File] = true
		}
	}
	for file, secret := range want {
		if !found[file] {
			t.Errorf("%s: %q not found; got %v", file, secret, secrets(got))
		}
	}

	ignored := map[string]string{
		"k8s/deploy.yaml": "spec:\n  secretName: db-credentials\n  existingSecret: my-secret\n  valueFrom:\n    secretKeyRef:\n      name: db-secret\n      key: password\n",
		"config/app.yaml": "auth:\n  tokenTtl: 3600\n  token_expiry: 1h\n  keyFile: /etc/ssl/key.pem\n  password_length: 12\n  publicKey: ssh-rsa-AAAAB3Nza\n",
		".env":            "TOKEN_LIMIT=1000\nSECRET=changeme\nAPI_KEY=${API_KEY}\nACCESS_TOKEN=\n",
		"src/auth.ts":     `const token = getToken(); if (token === "") {}; const label = "Your API key";`,
	}
	got, err = Scan(context.Background(), Options{Root: tree(t, ignored)})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 0 {
		t.Errorf("references, settings and placeholders flagged: %v", secrets(got))
	}
}

// Values starting with fake- or fakesecret- (mocks, tests, examples, CI) are skipped by every rule, with
// the built-in config, a project config extending it, and a config using gitleaks' deprecated [allowlist].
func TestFakePrefixAllowlisted(t *testing.T) {
	files := map[string]string{
		".env": "DB_PASSWORD=fake-db-password\nAPI_TOKEN=fakesecret-token-123\n" +
			"DATABASE_URL=postgres://app:fake-pw@localhost/app\nREAL_PASSWORD=Admin@123\n",
		"app.go": `password := "fake-pass-for-tests"` + "\n",
	}
	for name, config := range map[string]string{
		"built-in":   "",
		"useDefault": "[extend]\nuseDefault = true\n",
		"deprecated": "[allowlist]\npaths = ['''^vendor/''']\n",
	} {
		t.Run(name, func(t *testing.T) {
			f := maps.Clone(files)
			if config != "" {
				f[".gitleaks.toml"] = config
			}
			got, err := Scan(context.Background(), Options{Root: tree(t, f)})
			if err != nil {
				t.Fatal(err)
			}
			if want := []string{".env=Admin@123"}; !reflect.DeepEqual(secrets(got), want) {
				t.Errorf("Scan = %v, want %v", secrets(got), want)
			}
		})
	}
	set, err := Rules(t.TempDir(), "")
	if err != nil {
		t.Fatal(err)
	}
	if !slices.ContainsFunc(set.Allowlists, func(a AllowlistInfo) bool { return slices.Contains(a.Regexes, "^fake(?:secret)?-") }) {
		t.Errorf("fake- allowlist not listed: %+v", set.Allowlists)
	}
}

// Configuration-shaped values (paths, URLs without credentials, IPs, host:port, durations) under secret,
// token and password keys are not secrets; credentials inside URLs and self-chosen values still are.
func TestConfigShapedValuesSkipped(t *testing.T) {
	skipped := "# kube_webhook_token_auth_url: https://...\n" +
		"kube_webhook_token_auth_url: https://auth.example.internal/webhook\n" +
		"oidc_token_endpoint: https://sso.example.com/realms/x/protocol/openid-connect/token\n" +
		"vault_secret_path: /etc/vault/secret.json\n" +
		"client_secret_file: ./certs/client.pem\n" +
		"db_password_file: /run/secrets/db_password\n" +
		"token_server: 10.0.0.12:8200\n" +
		"secret_backend: vault.service.consul:8200\n" +
		"auth_token_cidr: 10.0.0.0/8\n" +
		"token_refresh: 30m\n" +
		"password_reset_url: https://app.example.com/reset\n"
	found := "CLIENT_SECRET: mysecret1\n" +
		"# api_token: Admin@123\n" +
		"token: https://hooks.example.com/x?key=abc123\n" +
		"admin_password: Pa55word!\n"
	got, err := Scan(context.Background(), Options{Root: tree(t, map[string]string{"group_vars/all.yml": skipped + found})})
	if err != nil {
		t.Fatal(err)
	}
	want := []string{
		"group_vars/all.yml=Admin@123", "group_vars/all.yml=Pa55word!",
		"group_vars/all.yml=https://hooks.example.com/x?key=abc123", "group_vars/all.yml=mysecret1",
	}
	if !reflect.DeepEqual(secrets(got), want) {
		t.Errorf("Scan = %v, want %v", secrets(got), want)
	}
	quoted := `{"tokenUrl": "https://sso.example.com/token", "secretPath": "/etc/app/secret", "apiKey": "k3y-Value_42"}` + "\n"
	got, err = Scan(context.Background(), Options{Root: tree(t, map[string]string{"app.json": quoted})})
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"app.json=k3y-Value_42"}; !reflect.DeepEqual(secrets(got), want) {
		t.Errorf("quoted: Scan = %v, want %v", secrets(got), want)
	}
}
