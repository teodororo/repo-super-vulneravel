## RSV (Repositório Super Vulnerável

**Gabarito:**

#### 1. SQL Injection: `build_lookup()` + `/user/search` e `/login`
**Onde:** `query = "SELECT * FROM " + table + " WHERE " + field + " = '" + value + "'"`

**Perigo:** Um atacante pode injetar `' OR '1'='1` ou encerrar a query e executar comandos adicionais.

#### 2. Command Injection: `run_diagnostics()` + `/ops/ping`
**Onde:** `subprocess.Popen(" ".join(parts), shell=True, ...)`

**Perigo:** Um atacante pode injetar: `localhost; cat /etc/passwd`.

#### 3. Insecure Deserialization (RCE): `load_profile()` + `/user/profile`
**Onde:** `pickle.loads(base64.b64decode(encoded_blob))`

**Perigo:** Um atacante pode enviar um objeto pickle malicioso codificado em base64 que executa código arbitrário ao ser desserializado.

#### 4. YAML Deserialization (RCE): `parse_config()` + `/admin/config`
**Onde:** `yaml.load(config_text, Loader=yaml.Loader)`

**Perigo:** `yaml.Loader` (full Loader) permite tags Python como `!!python/object/apply:os.system` que executam código arbitrário. Deveria usar `yaml.safe_load`.

#### 5. Path Traversal: `download_file()` + `/download`
**Onde:** `full_path = base_dir + filename`

**Perigo:** `filename` vem de `request.args` sem validação. Um atacante pode usar `../../etc/passwd` para ler arquivos arbitrários do sistema.

#### 6. SQL Injection secundário: `generate_report()`
**Onde:** `query = f"SELECT * FROM events WHERE ts BETWEEN '{start}' AND '{end}'"`

**Perigo:** `start` e `end` vêm de `request.args`, uma informação que vem do front. Validação client-side não tem valor de segurança no backend.

#### 7. Weak Hashing — `hash_value()`
**Onde:** `hashlib.md5(raw.encode()).hexdigest()`

**Perigo:** MD5 está quebrado criptograficamente e **nunca deve ser usado para senhas**. É vulnerável a rainbow tables e colisões.

#### 8. Hardcoded Secret
**Onde:** `app.secret_key = "dev-secret-2024"`

**Perigo:** A secret key do Flask é usada para assinar cookies de sessão. Com ela exposta no código, um atacante pode forjar sessões com qualquer `role`.