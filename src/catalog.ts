// Catastrophic and destructive commands beyond the coreutils: infrastructure as code, Kubernetes, cloud CLIs, containers,
// databases, ORMs and migration tools, object storage, hosting platforms, package registries and system administration.
// Each check receives the arguments that follow the command (and the VAR=value assignments before it) and returns a
// finding or null. "catastrophic" = broad and irreversible (destroy a stack, drop a database, delete a namespace);
// "destructive" = loses data or state but is scoped (delete one deployment, reset a local database, force a rollout).
import { Severity } from "./paths.js";

export interface Finding { sev: Severity; what: string }
type Env = Record<string, string>;
type Check = (rest: string[], env: Env) => Finding | null;
const cat = (what: string): Finding => ({ sev: "catastrophic", what });
const des = (what: string): Finding => ({ sev: "destructive", what });

/** Non-option arguments, skipping the value of the options in `valueOpts` (`-n prod`); everything after `--` counts. */
export function positionals(rest: string[], valueOpts: readonly string[] = []): string[] {
  const out: string[] = [];
  for (let k = 0; k < rest.length; k++) {
    const a = rest[k];
    if (a === "--") { out.push(...rest.slice(k + 1)); break; }
    if (a.length > 1 && a.startsWith("-")) { if (valueOpts.includes(a)) k++; continue; }
    out.push(a);
  }
  return out;
}
/** Values of options that take one: `-e X`, `-eX`, `--execute X`, `--execute=X`. */
export function optValues(rest: string[], names: readonly string[]): string[] {
  const out: string[] = [];
  for (let k = 0; k < rest.length; k++) {
    const a = rest[k];
    if (a === "--") break;
    for (const n of names) {
      if (a === n) { if (k + 1 < rest.length) out.push(rest[k + 1]); }
      else if (n.startsWith("--") && a.startsWith(n + "=")) out.push(a.slice(n.length + 1));
      else if (/^-[A-Za-z]$/.test(n) && a.length > 2 && a.startsWith(n) && a[1] !== "-") out.push(a.slice(2));
    }
  }
  return out;
}
/** One of `names` is present, alone or as `--name=value`. */
const has = (rest: string[], ...names: string[]) => rest.some(a => names.some(n => a === n || (n.startsWith("--") && a.startsWith(n + "="))));
/** A short flag, alone or combined (`-r`, `-rf`, `-fr`). */
const short = (rest: string[], c: string) => rest.some(a => /^-[A-Za-z]+$/.test(a) && a.slice(1).includes(c));
/** Arguments after the first occurrence of `word`. */
const after = (rest: string[], word: string) => rest.slice(rest.indexOf(word) + 1);
const isProd = (v: string | undefined) => !!v && /^prod(uction)?$/i.test(v);

// ---------------------------------------------------------------- infrastructure as code
const TF_VALUE_OPTS = ["-var", "-var-file", "-target", "-state", "-state-out", "-backup", "-lock-timeout", "-parallelism", "-replace", "-out"];
function terraform(name: string): Check {
  return rest => {
    const p = positionals(rest, TF_VALUE_OPTS); const [sub, sub2] = p;
    if (sub === "destroy" || sub === "destroy-all" || ((sub === "run-all" || sub === "run") && sub2 === "destroy")) return cat(`${name} destroy`);
    if (sub === "apply" && has(rest, "-destroy", "--destroy")) return cat(`${name} apply -destroy`);
    if ((sub === "apply" || sub === "apply-all" || ((sub === "run-all" || sub === "run") && sub2 === "apply")) && has(rest, "-auto-approve", "--auto-approve", "--terragrunt-non-interactive", "--non-interactive"))
      return des(`${name} apply -auto-approve (no human review of the plan)`);
    if (sub === "state" && (sub2 === "rm" || sub2 === "push")) return des(`${name} state ${sub2}`);
    if (sub === "workspace" && sub2 === "delete") return des(`${name} workspace delete`);
    if (sub === "taint" || sub === "force-unlock") return des(`${name} ${sub}`);
    return null;
  };
}
const PULUMI_VALUE_OPTS = ["-s", "--stack", "-C", "--cwd", "--target", "-t", "--config", "-c", "--config-file", "--parallel", "-p", "--message", "-m", "--refresh"];
const pulumi: Check = rest => {
  const p = positionals(rest, PULUMI_VALUE_OPTS);
  if (p[0] === "destroy" || p[0] === "down" || p[0] === "dn") return cat("pulumi destroy");
  if (p[0] === "stack" && (p[1] === "rm" || p[1] === "remove")) return cat("pulumi stack rm");
  if ((p[0] === "up" || p[0] === "update") && (has(rest, "--yes", "--skip-preview") || short(rest, "y") || short(rest, "f"))) return des("pulumi up --yes (no human review of the preview)");
  if (p[0] === "state" && p[1] === "delete") return des("pulumi state delete");
  return null;
};
const firstIs = (_name: string, words: string[], f: (p: string[]) => Finding): Check => rest => {
  const p = positionals(rest); return words.includes(p[0]) ? f(p) : null;
};

// ---------------------------------------------------------------- Kubernetes
const KUBE_VALUE_OPTS = ["-n", "--namespace", "--context", "--cluster", "--kubeconfig", "-l", "--selector", "-f", "--filename", "-o", "--output", "-c",
  "--container", "--field-selector", "--as", "--as-group", "-s", "--server", "--token", "--user", "-k", "--kustomize", "--timeout", "--grace-period",
  "--cascade", "--request-timeout", "--certificate-authority", "--client-certificate", "--client-key", "--tls-server-name", "--cache-dir", "-v", "--v", "--wait"];
/** Deleting one of these loses data, access or every object of a kind cluster-wide. */
const KUBE_CRITICAL = /^(namespaces?|ns|projects?|pv|persistentvolumes?|pvc|persistentvolumeclaims?|crds?|customresourcedefinitions?(\.apiextensions\.k8s\.io)?|nodes?|no|clusterroles?|clusterrolebindings?|storageclass(es)?|sc|validatingwebhookconfigurations?|mutatingwebhookconfigurations?|apiservices?)$/i;
const KUBE_READ = ["get", "logs", "describe", "explain", "top", "exec", "port-forward", "cp", "attach", "label", "annotate", "events", "diff", "wait"];
function kubectl(name: string): Check {
  return rest => {
    const p = positionals(rest, KUBE_VALUE_OPTS);
    if (p.includes("delete") && !KUBE_READ.includes(p[0])) {
      const kinds = after(p, "delete").flatMap(x => x.split(",")).map(x => x.split("/")[0]);
      if (has(rest, "--all", "--all-namespaces") || rest.includes("-A") || kinds.some(k => KUBE_CRITICAL.test(k))) return cat(`${name} delete ${kinds.find(k => KUBE_CRITICAL.test(k)) ?? "--all"}`);
      return des(`${name} delete`);
    }
    if (p[0] === "drain") return des(`${name} drain`);
    if (p[0] === "replace" && has(rest, "--force")) return des(`${name} replace --force`);
    if (p[0] === "apply" && has(rest, "--prune")) return des(`${name} apply --prune`);
    if (p[0] === "scale" && (rest.includes("--replicas=0") || after(rest, "--replicas")[0] === "0")) return des(`${name} scale --replicas=0`);
    return null;
  };
}
const helm: Check = rest => {
  const p = positionals(rest, ["-n", "--namespace", "--kube-context", "--kubeconfig", "--timeout"]);
  return /^(uninstall|delete|del|un)$/.test(p[0] ?? "") ? des(`helm ${p[0]}`) : null;
};

// ---------------------------------------------------------------- cloud CLIs
const AWS_VALUE_OPTS = ["--profile", "--region", "--output", "--endpoint-url", "--query", "--cli-input-json", "--cli-input-yaml", "--color", "--ca-bundle",
  "--cli-read-timeout", "--cli-connect-timeout", "--cli-binary-format"];
const AWS_CRITICAL = new Set(["terminate-instances", "delete-db-instance", "delete-db-cluster", "delete-global-cluster", "delete-table", "delete-stack",
  "delete-bucket", "delete-objects", "delete-cluster", "delete-file-system", "delete-volume", "delete-repository", "schedule-key-deletion",
  "delete-hosted-zone", "delete-backup-vault", "delete-db-snapshot", "delete-db-cluster-snapshot", "delete-user-pool", "delete-domain",
  "delete-replication-group", "delete-cache-cluster", "delete-stream", "delete-delivery-stream", "delete-secret", "delete-log-group",
  "delete-nodegroup", "delete-environment", "delete-graphql-api", "delete-workgroup", "delete-database", "delete-namespace", "delete-vault",
  "delete-recovery-point", "delete-backup", "delete-index", "delete-collection", "delete-account", "close-account", "delete-organization", "purge-queue"]);
const aws: Check = rest => {
  const p = positionals(rest, AWS_VALUE_OPTS); const [svc, op] = p;
  if (!svc || !op) return null;
  if (svc === "s3") {
    if (op === "rm") return has(rest, "--recursive") ? cat("aws s3 rm --recursive") : des("aws s3 rm");
    if (op === "rb") return has(rest, "--force") ? cat("aws s3 rb --force") : des("aws s3 rb");
    if ((op === "sync" || op === "mv") && has(rest, "--delete")) return des(`aws s3 ${op} --delete`);
    return null;
  }
  if (AWS_CRITICAL.has(op)) return cat(`aws ${svc} ${op}`);
  if (op === "delete" || /^(delete|terminate|purge|remove|deregister|reset|disable|stop|cancel|revoke|detach|disassociate|deactivate|reboot)-/.test(op)) return des(`aws ${svc} ${op}`);
  return null;
};
const GCLOUD_VALUE_OPTS = ["--project", "--account", "--configuration", "--format", "--verbosity", "--zone", "--region", "--impersonate-service-account",
  "--billing-project", "--flatten", "--filter", "--limit", "--page-size", "--sort-by", "--location", "--instance", "--cluster", "--database", "--trace-token"];
const GCLOUD_CRITICAL = /^(projects|sql instances|sql databases|container clusters|spanner (instances|databases)|bigtable (instances|tables)|redis instances|memcache instances|firestore databases|alloydb clusters|filestore instances|storage buckets|compute disks|compute snapshots|secrets|kms keys|bigquery datasets|dataproc clusters|composer environments|artifacts repositories)$/;
const gcloud: Check = rest => {
  const p = positionals(rest, GCLOUD_VALUE_OPTS).filter(x => !/^(alpha|beta|preview)$/.test(x));
  if (p[0] === "storage" && p[1] === "rm") return has(rest, "--recursive") || short(rest, "r") || short(rest, "R") || p.some(x => x.endsWith("/**")) ? cat("gcloud storage rm --recursive") : des("gcloud storage rm");
  const k = p.findIndex(x => x === "delete" || x === "purge");
  if (k > 0) { const path = p.slice(0, k).join(" "); return GCLOUD_CRITICAL.test(path) ? cat(`gcloud ${path} ${p[k]}`) : des(`gcloud ${path} ${p[k]}`); }
  return null;
};
const gsutil: Check = rest => {
  const p = positionals(rest, ["-o", "-h", "-u", "-i"]); const sub = p[0]; if (!sub) return null;
  const a = after(rest, sub);
  if (sub === "rm") return short(a, "r") || short(a, "R") || has(a, "--recursive") || a.some(x => /^gs:\/\/[^\/]+\/?(\*\*?)?$/.test(x) || x.endsWith("/**")) ? cat("gsutil rm -r") : des("gsutil rm");
  if (sub === "rb") return cat("gsutil rb");
  if (sub === "rsync" && short(a, "d")) return des("gsutil rsync -d");
  return null;
};
const bq: Check = rest => {
  const p = positionals(rest, ["--project_id", "--location", "--dataset_id", "--format"]);
  return p[0] === "rm" ? (short(rest, "r") || has(rest, "--recursive") ? cat("bq rm -r") : des("bq rm")) : null;
};
const AZ_VALUE_OPTS = ["--subscription", "-o", "--output", "--query", "-g", "--resource-group", "-n", "--name", "--ids", "-l", "--location", "--account-name",
  "--container-name", "--source", "--pattern", "--vault-name", "--server", "-s", "--workspace-name", "--account-key", "--connection-string", "--sas-token"];
const AZ_CRITICAL = /^(group|sql server|sql db|sql mi|cosmosdb|cosmosdb (sql|mongodb|cassandra|gremlin|table) (database|keyspace|graph|table)|storage account|storage container|aks|keyvault|postgres (flexible-)?server|mysql (flexible-)?server|redis|monitor log-analytics workspace|backup vault|disk|snapshot|sig|acr|servicebus namespace|eventhubs namespace)$/;
const az: Check = rest => {
  const p = positionals(rest, AZ_VALUE_OPTS);
  const k = p.findIndex(x => /^(delete|purge|delete-batch)$/.test(x));
  if (k <= 0) return null;
  const path = p.slice(0, k).join(" ");
  return AZ_CRITICAL.test(path) || p[k] !== "delete" ? cat(`az ${path} ${p[k]}`) : des(`az ${path} ${p[k]}`);
};
/** Other cloud CLIs: any delete is destructive; deleting a database, cluster, volume or project is catastrophic. */
function cloud(name: string, critical: RegExp): Check {
  return rest => {
    const p = positionals(rest, ["-o", "--output", "--format", "--context", "--profile", "--region", "-r", "--config", "--project", "--token", "-t"]);
    const k = p.findIndex(x => /^(delete|destroy|rm|remove|terminate|purge)$/.test(x));
    if (k <= 0) return null;
    const path = p.slice(0, k).join(" ");
    return critical.test(path) ? cat(`${name} ${path} ${p[k]}`) : des(`${name} ${path} ${p[k]}`);
  };
}
const CLOUD_CRITICAL = /(^|\s)(databases?|db|clusters?|kubernetes( cluster)?|volumes?|projects?|buckets?|accounts?|storage)$/;

// ---------------------------------------------------------------- containers
const DOCKER_VALUE_OPTS = ["-H", "--host", "--context", "-c", "--config", "--log-level", "-l", "--tlscacert", "--tlscert", "--tlskey",
  "-f", "--file", "-p", "--project-name", "--profile", "--env-file", "--project-directory", "--ansi", "--parallel", "--progress", "--filter", "-t", "--timeout", "--rmi"];
const composeDownVolumes = (rest: string[]) => { const a = after(rest, "down"); return has(a, "--volumes") || short(a, "v"); };
function docker(name: string): Check {
  return rest => {
    const p = positionals(rest, DOCKER_VALUE_OPTS);
    if (p[0] === "system" && p[1] === "prune") return has(rest, "--volumes") ? cat(`${name} system prune --volumes`) : des(`${name} system prune`);
    if (p[0] === "volume" && (p[1] === "rm" || p[1] === "remove")) return des(`${name} volume rm`);
    if (p[0] === "volume" && p[1] === "prune") return has(rest, "--all") || short(after(rest, "prune"), "a") ? cat(`${name} volume prune --all`) : des(`${name} volume prune`);
    if (p[0] === "compose" && p[1] === "down" && composeDownVolumes(rest)) return des(`${name} compose down --volumes (deletes the volumes and their data)`);
    if (p[0] === "stack" && /^(rm|remove|down)$/.test(p[1] ?? "")) return des(`${name} stack rm`);
    if (p[0] === "swarm" && p[1] === "leave" && has(rest, "--force")) return des(`${name} swarm leave --force`);
    return null;
  };
}
const dockerCompose: Check = rest => (positionals(rest, DOCKER_VALUE_OPTS)[0] === "down" && composeDownVolumes(rest) ? des("docker-compose down --volumes (deletes the volumes and their data)") : null);

// ---------------------------------------------------------------- databases and data stores
const MONGO_DROP = /\.\s*dropDatabase\s*\(|\.\s*drop\s*\(\s*\)|\.\s*(deleteMany|remove)\s*\(\s*(\{\s*\})?\s*\)|\.\s*drop(Collection|Index(es)?)\s*\(/;
const mongo: Check = rest => {
  const code = optValues(rest, ["--eval"]).join("\n");
  return MONGO_DROP.test(code) ? cat("mongo shell dropping a database, a collection or every document") : null;
};
const redis: Check = rest => {
  const p = positionals(rest, ["-h", "-p", "-a", "-n", "-u", "--user", "--pass", "-s", "-r", "-i", "-d", "--sni", "--cacert", "--cert", "--key", "--tls-ciphers"]);
  const c = p.find(x => /^(flushall|flushdb)$/i.test(x));
  return c ? cat(`redis-cli ${c.toUpperCase()}`) : null;
};
const cqlsh: Check = rest => (/\b(drop\s+(keyspace|table|schema)|truncate)\b/i.test(optValues(rest, ["-e", "--execute"]).join(";")) ? cat("cqlsh DROP/TRUNCATE") : null);
const etcdctl: Check = rest => {
  const p = positionals(rest, ["--endpoints", "--user", "--password", "--cacert", "--cert", "--key", "-w", "--write-out"]);
  if (p[0] !== "del") return null;
  return has(rest, "--prefix", "--from-key") && (p.length < 2 || p[1] === "" || p[1] === "/") ? cat("etcdctl del --prefix (every key)") : des("etcdctl del");
};
const consul: Check = rest => {
  const p = positionals(rest);
  return p[0] === "kv" && p[1] === "delete" ? (has(rest, "-recurse", "--recurse") ? cat("consul kv delete -recurse") : des("consul kv delete")) : null;
};
const vault: Check = rest => {
  const p = positionals(rest, ["-address", "-namespace", "-mount", "-format"]);
  if (p[0] === "secrets" && p[1] === "disable") return cat("vault secrets disable (destroys every secret of the mount)");
  if ((p[0] === "kv" && (p[1] === "destroy" || (p[1] === "metadata" && p[2] === "delete"))) || p[0] === "delete") return des(`vault ${p.slice(0, p[0] === "kv" ? (p[1] === "metadata" ? 3 : 2) : 1).join(" ")}`);
  return null;
};
const influx: Check = rest => {
  const p = positionals(rest, ["--org", "-o", "--host", "--token", "-t", "--bucket", "-b", "--start", "--stop", "--predicate"]);
  if ((p[0] === "bucket" || p[0] === "org") && p[1] === "delete") return cat(`influx ${p[0]} delete`);
  return p[0] === "delete" ? des("influx delete") : null;
};

// ---------------------------------------------------------------- ORMs, migration tools and frameworks
const prisma: Check = rest => {
  const p = positionals(rest, ["--schema"]);
  if (p[0] === "migrate" && p[1] === "reset") return cat("prisma migrate reset (drops the database)");
  if (p[0] === "db" && p[1] === "push" && has(rest, "--force-reset")) return cat("prisma db push --force-reset (drops the database)");
  if (p[0] === "db" && p[1] === "push" && has(rest, "--accept-data-loss")) return des("prisma db push --accept-data-loss");
  return null;
};
const RAILS_DB = /^db:(drop|reset|purge|schema:load|structure:load|migrate:reset|truncate_all|seed:replant)(\[.*)?$/;
const rails: Check = (rest, env) => {
  const t = positionals(rest, ["-e", "--environment"]).find(x => RAILS_DB.test(x)); if (!t) return null;
  const prod = isProd(env.RAILS_ENV) || isProd(env.RACK_ENV) || optValues(rest, ["-e", "--environment"]).some(isProd) || env.DISABLE_DATABASE_ENVIRONMENT_CHECK === "1";
  return prod ? cat(`rails ${t} in production`) : des(`rails ${t}`);
};
const artisan: Check = rest => {
  const t = positionals(rest, ["--env", "--database", "--path"])[0] ?? "";
  if (!/^(migrate:(fresh|reset|refresh)|db:wipe)$/.test(t)) return null;
  return has(rest, "--force") ? cat(`artisan ${t} --force`) : des(`artisan ${t}`);
};
const django: Check = rest => {
  const p = positionals(rest, ["--settings", "--database", "--pythonpath"]);
  if (/^(flush|reset_db|reset_schema|sqlflush)$/.test(p[0] ?? "") && p[0] !== "sqlflush") return has(rest, "--noinput", "--no-input") ? cat(`django ${p[0]} --noinput`) : des(`django ${p[0]}`);
  if (p[0] === "migrate" && p[2] === "zero") return des(`django migrate ${p[1]} zero`);
  return null;
};
const supabase: Check = rest => {
  const p = positionals(rest, ["--db-url", "--workdir", "--project-ref", "-p", "--password", "--schema", "-s"]);
  if (p[0] === "db" && p[1] === "reset") return has(rest, "--linked", "--db-url") ? cat("supabase db reset on a linked/remote database") : des("supabase db reset");
  if (p[0] === "projects" && p[1] === "delete") return cat("supabase projects delete");
  if (p[0] === "storage" && p[1] === "rm") return short(rest, "r") || has(rest, "--recursive") ? cat("supabase storage rm -r") : des("supabase storage rm");
  const k = p.indexOf("delete");
  return k > 0 ? des(`supabase ${p.slice(0, k + 1).join(" ")}`) : null;
};
const symfony: Check = rest => {
  const t = positionals(rest, ["--env", "-e", "--connection", "--em"])[0] ?? "";
  if (/^doctrine:(database|schema):drop$/.test(t)) return cat(`console ${t}`);
  if (t === "doctrine:fixtures:load" && !has(rest, "--append")) return des("console doctrine:fixtures:load (purges the database)");
  return null;
};
const adonis: Check = rest => {
  const t = positionals(rest)[0] ?? "";
  return /^(migration:fresh|migration:reset|db:wipe)$/.test(t) ? (has(rest, "--force") ? cat(`ace ${t} --force`) : des(`ace ${t}`)) : null;
};
const word = (name: string, re: RegExp, sev: Severity, label?: string): Check => rest => {
  const t = positionals(rest).find(x => re.test(x));
  return t ? { sev, what: label ?? `${name} ${t}` } : null;
};
const mix: Check = (rest, env) => {
  const t = positionals(rest).find(x => /^ecto\.(drop|reset)$/.test(x)); if (!t) return null;
  return isProd(env.MIX_ENV) ? cat(`mix ${t} in production`) : des(`mix ${t}`);
};

// ---------------------------------------------------------------- object storage
const mc: Check = rest => {
  const p = positionals(rest, ["--config-dir", "-C"]);
  if (p[0] === "rm") return has(rest, "--recursive") || short(rest, "r") ? cat("mc rm --recursive") : des("mc rm");
  if (p[0] === "rb") return cat("mc rb");
  if (p[0] === "mirror" && has(rest, "--remove")) return des("mc mirror --remove");
  return null;
};
const rclone: Check = rest => {
  const p = positionals(rest, ["--config", "--include", "--exclude", "--filter", "--max-age", "--min-age"]);
  if (p[0] === "purge") return cat("rclone purge");
  if (/^(delete|deletefile|rmdirs)$/.test(p[0] ?? "")) return des(`rclone ${p[0]}`);
  if (p[0] === "sync") return des("rclone sync (deletes files missing from the source at the destination)");
  return null;
};
const s3cmd: Check = rest => {
  const p = positionals(rest, ["-c", "--config"]);
  if (p[0] === "del" || p[0] === "rm") return has(rest, "--recursive") || short(rest, "r") ? cat("s3cmd del --recursive") : des("s3cmd del");
  if (p[0] === "rb") return cat("s3cmd rb");
  if (p[0] === "sync" && has(rest, "--delete-removed")) return des("s3cmd sync --delete-removed");
  return null;
};
const azcopy: Check = rest => {
  const p = positionals(rest);
  if (p[0] === "remove" || p[0] === "rm") return has(rest, "--recursive") ? cat("azcopy remove --recursive") : des("azcopy remove");
  if (p[0] === "sync" && rest.some(a => /^--delete-destination=(true|prompt)$/i.test(a))) return des("azcopy sync --delete-destination");
  return null;
};

// ---------------------------------------------------------------- HTTP APIs
const CURL_VALUE_OPTS = ["-X", "--request", "-H", "--header", "-d", "--data", "--data-raw", "--data-binary", "--data-urlencode", "-u", "--user", "-o", "--output",
  "-A", "--user-agent", "-e", "--referer", "-b", "--cookie", "-c", "--cookie-jar", "-F", "--form", "-T", "--upload-file", "--cacert", "--cert", "--key",
  "-m", "--max-time", "--connect-timeout", "-x", "--proxy", "-w", "--write-out", "--retry", "--resolve", "--url"];
const curl: Check = rest => {
  const methods = optValues(rest, ["-X", "--request"]);
  if (!methods.some(m => /^delete$/i.test(m))) return null;
  const urls = [...positionals(rest, CURL_VALUE_OPTS), ...optValues(rest, ["--url"])];
  return urls.some(u => /\/(_all|\*)\/?(\?|$)/.test(u)) ? cat("curl -X DELETE on every index") : des("HTTP DELETE request (curl -X DELETE)");
};
const httpie: Check = rest => (positionals(rest)[0]?.toUpperCase() === "DELETE" ? des("HTTP DELETE request (httpie)") : null);
const wget: Check = rest => (optValues(rest, ["--method"]).some(m => /^delete$/i.test(m)) ? des("HTTP DELETE request (wget --method=DELETE)") : null);

// ---------------------------------------------------------------- hosting platforms and registries
const heroku: Check = rest => {
  const c = positionals(rest, ["-a", "--app", "-r", "--remote", "--confirm"])[0] ?? "";
  if (/^(apps:destroy|apps:delete|destroy|pg:reset|addons:destroy|addons:remove|redis:reset|pg:killall)$/.test(c)) return cat(`heroku ${c}`);
  if (/^(pg:backups:delete|config:unset|domains:remove|releases:rollback)$/.test(c)) return des(`heroku ${c}`);
  return null;
};
function fly(name: string): Check {
  return rest => {
    const p = positionals(rest, ["-a", "--app", "-c", "--config", "-r", "--region", "-o", "--org"]);
    if (p[0] === "destroy" || ((p[0] === "apps" || p[0] === "app") && /^(destroy|delete|remove)$/.test(p[1] ?? "")) || ((p[0] === "volumes" || p[0] === "volume" || p[0] === "vol") && /^(destroy|delete)$/.test(p[1] ?? ""))
      || ((p[0] === "postgres" || p[0] === "pg" || p[0] === "mpg") && p[1] === "destroy")) return cat(`${name} ${p.slice(0, 2).join(" ")}`);
    if ((/^(machines?|m)$/.test(p[0] ?? "") && /^(destroy|remove|rm)$/.test(p[1] ?? "")) || (p[0] === "secrets" && p[1] === "unset")) return des(`${name} ${p.slice(0, 2).join(" ")}`);
    return null;
  };
}
function vercel(name: string): Check {
  return rest => {
    const p = positionals(rest, ["--scope", "--token", "-t", "--team", "-S"]);
    if ((p[0] === "project" || p[0] === "projects") && /^(rm|remove)$/.test(p[1] ?? "")) return cat(`${name} project rm`);
    if (p[0] === "remove" || p[0] === "rm") return des(`${name} remove`);
    if (/^(env|domains?|dns|certs?|alias)$/.test(p[0] ?? "") && /^(rm|remove)$/.test(p[1] ?? "")) return des(`${name} ${p[0]} rm`);
    return null;
  };
}
function netlify(name: string): Check {
  return rest => {
    const c = positionals(rest, ["--site", "--auth", "--context"])[0] ?? "";
    if (c === "sites:delete") return cat(`${name} sites:delete`);
    return c === "env:unset" ? des(`${name} env:unset`) : null;
  };
}
const firebase: Check = rest => {
  const c = positionals(rest, ["--project", "-P", "--token", "--only", "--database", "--instance"])[0] ?? "";
  if (c === "firestore:delete") return has(rest, "--all-collections", "--recursive") || short(rest, "r") ? cat("firebase firestore:delete --recursive") : des("firebase firestore:delete");
  if (c === "database:remove") return cat("firebase database:remove");
  if (/^(hosting:disable|functions:delete|remoteconfig:rollback|ext:uninstall)$/.test(c)) return des(`firebase ${c}`);
  return null;
};
const wrangler: Check = rest => {
  const p = positionals(rest, ["--env", "-e", "--config", "-c", "--name", "--account-id", "--binding", "--namespace-id", "--preview-id"]);
  if (p.includes("delete") && (p[0] === "d1" || (p[0] === "r2" && p[1] === "bucket") || (p[0] === "kv" && /^(namespace|kv:namespace)$/.test(p[1] ?? "")) || p[0] === "queues" || p[0] === "vectorize" || p[0] === "hyperdrive"))
    return cat(`wrangler ${p.slice(0, p.indexOf("delete") + 1).join(" ")}`);
  if (p[0] === "delete" || p.includes("delete")) return des(`wrangler ${p.slice(0, p.indexOf("delete") + 1).join(" ")}`);
  return null;
};
const railway: Check = rest => {
  const p = positionals(rest, ["-s", "--service", "-e", "--environment"]);
  if (p[0] === "delete") return cat("railway delete");
  return p[0] === "down" ? des("railway down") : null;
};
function gitForge(name: string): Check {
  return rest => {
    const p = positionals(rest, ["-R", "--repo", "-X", "--method", "-H", "--header", "-f", "--field", "-F", "--raw-field", "--hostname"]);
    if (p[0] === "repo" && p[1] === "delete") return cat(`${name} repo delete`);
    if (p[0] === "api" && optValues(rest, ["-X", "--method"]).some(m => /^delete$/i.test(m))) return des(`${name} api --method DELETE`);
    if (/^(release|secret|variable|cache|run|ssh-key|gpg-key|label|deploy-key)$/.test(p[0] ?? "") && /^(delete|remove|rm)$/.test(p[1] ?? "")) return des(`${name} ${p[0]} delete`);
    return null;
  };
}
const npm: Check = rest => {
  const p = positionals(rest, ["--registry", "--otp", "--tag", "-w", "--workspace"]);
  if (p[0] !== "unpublish") return null;
  const spec = p[1] ?? "";
  return has(rest, "--force") || !/^@?[^@]+@.+/.test(spec) ? cat("npm unpublish of a whole package") : des(`npm unpublish ${spec}`);
};

// ---------------------------------------------------------------- system administration
const power = (name: string): Check => rest => (rest.some(a => /^-c$|^--cancel$/.test(a)) ? null : des(`${name} (the machine stops)`));
const systemctl: Check = rest => {
  const p = positionals(rest, ["-H", "--host", "-M", "--machine", "-t", "--type", "-p", "--property", "-s", "--signal"]);
  return /^(poweroff|reboot|halt|kexec|rescue|emergency|soft-reboot)$/.test(p[0] ?? "") ? des(`systemctl ${p[0]}`) : null;
};
const telinit = (name: string): Check => rest => (/^[06sS]$/.test(positionals(rest)[0] ?? "") ? des(`${name} ${positionals(rest)[0]}`) : null);
const kill: Check = rest => {
  const k = rest.lastIndexOf("-1");
  if (k < 0) return null;
  const before = rest.slice(0, k);
  return before.includes("--") || before.some(a => /^-(9|KILL|SIGKILL|TERM|SIGTERM|15|s|n)$/i.test(a)) ? cat("kill -1 (every process of the user, or of the machine as root)") : null;
};
const crontab: Check = rest => (short(rest, "r") ? des("crontab -r (removes every cron job)") : null);
const iptables = (name: string): Check => rest => (has(rest, "-F", "--flush", "-X", "--delete-chain") || short(rest, "F") || (has(rest, "-P", "--policy") && rest.some(a => /^(DROP|REJECT)$/.test(a))) ? des(`${name} flush/drop policy`) : null);
const nft: Check = rest => { const p = positionals(rest); return p[0] === "flush" && p[1] === "ruleset" ? des("nft flush ruleset") : null; };
const ufw: Check = rest => (/^(reset|disable)$/.test(positionals(rest)[0] ?? "") ? des(`ufw ${positionals(rest)[0]}`) : null);

/** Command name (base name, lower case, without .exe/.cmd) -> check. */
const CATALOG: Record<string, Check> = {
  terraform: terraform("terraform"), tofu: terraform("tofu"), opentofu: terraform("opentofu"), terragrunt: terraform("terragrunt"),
  pulumi,
  cdk: firstIs("cdk", ["destroy"], () => cat("cdk destroy")), cdktf: firstIs("cdktf", ["destroy"], () => cat("cdktf destroy")),
  serverless: firstIs("serverless", ["remove"], () => cat("serverless remove")), sls: firstIs("sls", ["remove"], () => cat("serverless remove")),
  sam: firstIs("sam", ["delete"], () => cat("sam delete")),
  eksctl: rest => { const p = positionals(rest, ["--name", "--region", "--profile", "-f", "--config-file", "--cluster"]); return p[0] === "delete" ? (p[1] === "cluster" ? cat("eksctl delete cluster") : des(`eksctl delete ${p[1] ?? ""}`.trim())) : null; },
  copilot: rest => { const p = positionals(rest, ["-n", "--name", "-a", "--app", "-e", "--env"]); return p.includes("delete") ? (/^(app|env)$/.test(p[0] ?? "") ? cat(`copilot ${p[0]} delete`) : des(`copilot ${p[0]} delete`)) : null; },
  kubectl: kubectl("kubectl"), oc: kubectl("oc"), kubecolor: kubectl("kubectl"), helm,
  argocd: rest => { const p = positionals(rest, ["--server", "--auth-token", "-N", "--app-namespace"]); return /^(delete|rm)$/.test(p[1] ?? "") ? des(`argocd ${p[0]} ${p[1]}`) : null; },
  aws, gcloud, gsutil, bq, az,
  doctl: cloud("doctl", CLOUD_CRITICAL), "linode-cli": cloud("linode-cli", CLOUD_CRITICAL), hcloud: cloud("hcloud", CLOUD_CRITICAL), scw: cloud("scw", CLOUD_CRITICAL),
  oci: cloud("oci", CLOUD_CRITICAL), ibmcloud: cloud("ibmcloud", CLOUD_CRITICAL), exo: cloud("exo", CLOUD_CRITICAL), civo: cloud("civo", CLOUD_CRITICAL),
  "vultr-cli": cloud("vultr-cli", CLOUD_CRITICAL), upctl: cloud("upctl", CLOUD_CRITICAL), kind: cloud("kind", /^$/), minikube: firstIs("minikube", ["delete"], () => des("minikube delete")),
  k3d: cloud("k3d", /^$/),
  docker: docker("docker"), podman: docker("podman"), nerdctl: docker("nerdctl"), "docker-compose": dockerCompose, "podman-compose": dockerCompose,
  dropdb: () => cat("dropdb"), dropuser: () => des("dropuser"), pg_dropcluster: () => cat("pg_dropcluster"),
  mysqladmin: rest => (positionals(rest, ["-u", "--user", "-h", "--host", "-P", "--port", "-S", "--socket"]).some(x => /^drop$/i.test(x)) ? cat("mysqladmin drop") : null),
  mariadb_admin: rest => (positionals(rest).some(x => /^drop$/i.test(x)) ? cat("mariadb-admin drop") : null),
  "mariadb-admin": rest => (positionals(rest).some(x => /^drop$/i.test(x)) ? cat("mariadb-admin drop") : null),
  "redis-cli": redis, "valkey-cli": redis, mongosh: mongo, mongo, cqlsh, etcdctl, consul, vault, influx,
  prisma, rails, rake: rails, artisan, "manage.py": django, "django-admin": django, supabase,
  flyway: word("flyway", /^clean$/, "catastrophic", "flyway clean (drops every object of the schemas)"),
  liquibase: word("liquibase", /^(drop-?all|dropAll)$/i, "catastrophic", "liquibase dropAll"),
  sequelize: rest => { const t = positionals(rest)[0] ?? ""; return t === "db:drop" ? cat("sequelize db:drop") : /^db:(migrate|seed):undo:all$/.test(t) ? des(`sequelize ${t}`) : null; },
  "sequelize-cli": rest => { const t = positionals(rest)[0] ?? ""; return t === "db:drop" ? cat("sequelize db:drop") : /^db:(migrate|seed):undo:all$/.test(t) ? des(`sequelize ${t}`) : null; },
  typeorm: word("typeorm", /^schema:drop$/, "catastrophic"), "typeorm-ts-node-commonjs": word("typeorm", /^schema:drop$/, "catastrophic"),
  "typeorm-ts-node-esm": word("typeorm", /^schema:drop$/, "catastrophic"),
  knex: rest => (positionals(rest)[0] === "migrate:rollback" && has(rest, "--all") ? des("knex migrate:rollback --all") : null),
  alembic: rest => { const p = positionals(rest, ["-c", "--config", "-n", "--name", "-x"]); return p[0] === "downgrade" && p[1] === "base" ? des("alembic downgrade base") : null; },
  "drizzle-kit": word("drizzle-kit", /^drop$/, "destructive"),
  "mikro-orm": word("mikro-orm", /^(schema:drop|schema:fresh|migration:fresh)$/, "catastrophic"),
  dbmate: word("dbmate", /^drop$/, "catastrophic"),
  goose: rest => { const p = positionals(rest, ["-dir", "-table"]); return p.includes("reset") ? des("goose reset") : p.includes("down-to") && p.at(-1) === "0" ? des("goose down-to 0") : null; },
  migrate: word("migrate", /^drop$/, "catastrophic", "migrate drop (drops everything in the database)"),
  atlas: rest => { const p = positionals(rest, ["-u", "--url", "--env", "-c", "--config"]); return p[0] === "schema" && p[1] === "clean" ? cat("atlas schema clean") : null; },
  sqlx: rest => { const p = positionals(rest, ["-D", "--database-url"]); return p[0] === "database" && (p[1] === "drop" || p[1] === "reset") ? cat(`sqlx database ${p[1]}`) : null; },
  dotnet: rest => { const p = positionals(rest, ["-p", "--project", "-s", "--startup-project", "-c", "--context", "--connection"]); return p[0] === "ef" && p[1] === "database" && p[2] === "drop" ? cat("dotnet ef database drop") : null; },
  "dotnet-ef": rest => { const p = positionals(rest, ["-p", "--project", "-s", "--startup-project", "-c", "--context"]); return p[0] === "database" && p[1] === "drop" ? cat("dotnet ef database drop") : null; },
  mix, diesel: rest => { const p = positionals(rest, ["--database-url"]); return p[0] === "database" && p[1] === "reset" ? des("diesel database reset") : null; },
  wp: rest => { const p = positionals(rest, ["--path", "--url", "--user"]); return (p[0] === "db" && /^(drop|reset|clean)$/.test(p[1] ?? "")) || (p[0] === "site" && p[1] === "empty") ? cat(`wp ${p[0]} ${p[1]}`) : null; },
  drush: word("drush", /^(sql:drop|sql-drop|site:install|site-install|si)$/, "catastrophic"),
  console: symfony, ace: adonis,
  mc, rclone, s3cmd, azcopy,
  curl, http: httpie, https: httpie, xh: httpie, wget,
  heroku, fly: fly("fly"), flyctl: fly("flyctl"), vercel: vercel("vercel"), vc: vercel("vercel"), netlify: netlify("netlify"), ntl: netlify("netlify"),
  firebase, wrangler, railway, gh: gitForge("gh"), glab: gitForge("glab"), npm,
  shutdown: power("shutdown"), reboot: power("reboot"), halt: power("halt"), poweroff: power("poweroff"), systemctl,
  init: telinit("init"), telinit: telinit("telinit"), kill, killall5: () => cat("killall5 (every process)"), crontab,
  userdel: () => des("userdel"), deluser: () => des("deluser"), iptables: iptables("iptables"), ip6tables: iptables("ip6tables"), nft, ufw,
};
const catalogName = (cmd: string) => cmd.replace(/^.*[\/\\]/, "").toLowerCase().replace(/\.(exe|cmd|bat|ps1)$/, "");
/** Is this command one the catalog knows (whatever its arguments)? */
export const inCatalog = (cmd: string) => Object.hasOwn(CATALOG, catalogName(cmd));
/** Catalog finding for one command (name as typed: path, case and .exe suffix are normalized), or null. */
export function catalogFinding(cmd: string, rest: string[], env: Env = {}): Finding | null {
  const name = catalogName(cmd);
  const check = Object.hasOwn(CATALOG, name) ? CATALOG[name] : undefined;
  return check ? check(rest, env) : null;
}

// ---------------------------------------------------------------- SQL passed to database clients
/** Database clients and how they take SQL text: option values and, for some, positional arguments after the database. */
const SQL_CLIENTS: Record<string, { opts?: string[]; valueOpts?: string[]; positionalFrom?: number; after?: string[] }> = {
  psql: { opts: ["-c", "--command"] }, mysql: { opts: ["-e", "--execute"] }, mariadb: { opts: ["-e", "--execute"] },
  sqlite3: { opts: ["-cmd"], valueOpts: ["-cmd", "-separator", "-newline", "-nullvalue", "-init", "-vfs", "-maxsize", "-mmap", "-pagecache", "-lookaside", "-heap"], positionalFrom: 1 },
  duckdb: { opts: ["-c", "-cmd", "-s"], valueOpts: ["-c", "-cmd", "-s", "-init", "-separator", "-newline", "-nullvalue"], positionalFrom: 1 },
  "clickhouse-client": { opts: ["-q", "--query"] }, sqlcmd: { opts: ["-Q", "-q"] }, cockroach: { opts: ["-e", "--execute"] },
  snowsql: { opts: ["-q", "--query"] }, usql: { opts: ["-c", "--command"] }, "mssql-cli": { opts: ["-Q", "--query"] },
  trino: { opts: ["--execute"] }, presto: { opts: ["--execute"] }, "databricks": { opts: ["--statement"] },
  bq: { after: ["query"], valueOpts: ["--project_id", "--location", "--format", "--max_rows", "--parameter"] },
  turso: { after: ["shell"], positionalFrom: 1 }, wrangler: { opts: ["--command"] }, heroku: { opts: ["-c", "--command"] },
  clickhouse: { opts: ["-q", "--query"] },
};
/** Database clients read in one command: each reads the rest of the command, so thousands of "psql" words were quadratic. */
export const SQL_CLIENTS_READ = 16;
/**
 * SQL texts given to a database client somewhere in `argv` (also behind sudo, env, docker exec, kubectl exec...).
 * `more`: the command names more clients than are read (SQL_CLIENTS_READ); the caller treats it as SQL it cannot see.
 */
export function clientSql(argv: string[]): { sql: string[]; more: boolean } {
  const out: string[] = [];
  let seen = 0;
  for (let i = 0; i < argv.length; i++) {
    const name = argv[i].replace(/^.*[\/\\]/, "").toLowerCase().replace(/\.exe$/, "");
    const spec = Object.hasOwn(SQL_CLIENTS, name) ? SQL_CLIENTS[name] : undefined; if (!spec) continue;
    if (++seen > SQL_CLIENTS_READ) return { sql: out, more: true };
    const rest = argv.slice(i + 1);
    if (spec.opts) out.push(...optValues(rest, spec.opts));
    if (spec.positionalFrom !== undefined || spec.after) {
      let p = positionals(rest, spec.valueOpts ?? []);
      if (spec.after) { const k = p.findIndex(x => spec.after!.includes(x)); if (k < 0) continue; p = p.slice(k + 1); }
      out.push(...p.slice(spec.positionalFrom ?? 0));
    }
  }
  return { sql: out, more: false };
}
