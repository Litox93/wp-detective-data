// build.js — descarrega a base de dados da Wordfence e divide-a em ficheiros pequenos por letra.
// Exemplo: os plugins começados por "c" ficam em data/plugins/c.json.
// A extensão só descarrega o ficheiro da letra de que precisa.
const fs = require("fs");
const zlib = require("zlib");

const FEED_URL = "https://www.wordfence.com/api/intelligence/v3/vulnerabilities/production";
const KEY = process.env.WORDFENCE_API_KEY;

main().catch((err) => {
  console.error("ERRO:", err.message);
  process.exit(1);
});

async function main() {
  if (!KEY) throw new Error("Falta o segredo WORDFENCE_API_KEY nas definições do repositório.");

  console.log("A descarregar a base de dados da Wordfence...");
  const res = await fetch(FEED_URL, { headers: { Authorization: "Bearer " + KEY } });
  if (!res.ok) throw new Error("A Wordfence respondeu " + res.status + ": " + (await res.text()).slice(0, 300));

  let buf = Buffer.from(await res.arrayBuffer());
  if (buf[0] === 0x1f && buf[1] === 0x8b) buf = zlib.gunzipSync(buf); // ficheiro comprimido
  console.log("Descarregados " + (buf.length / 1e6).toFixed(1) + " MB");

  const records = parseRecords(buf.toString("utf8"));
  if (!records.length) throw new Error("Não consegui ler nenhum registo. O formato do feed pode ter mudado.");
  console.log("Registos lidos: " + records.length);
  console.log("Exemplo de registo (para diagnóstico):\n" + JSON.stringify(records[0]).slice(0, 1500));

  const shards = { plugins: {}, themes: {} };
  const notices = new Map();
  let entries = 0;

  for (const r of records) {
    if (r.copyrights) notices.set(JSON.stringify(r.copyrights), r.copyrights);
    for (const sw of r.software || []) {
      const kind = sw.type === "plugin" ? "plugins" : sw.type === "theme" ? "themes" : null;
      if (!kind || !sw.slug) continue;
      const slug = String(sw.slug).toLowerCase();
      const ranges = Object.values(sw.affected_versions || {}).map((v) => [
        v.from_version ?? "*",
        v.from_inclusive !== false,
        v.to_version ?? "*",
        v.to_inclusive !== false,
      ]);
      if (!ranges.length) continue;

      const shard = shardOf(slug);
      shards[kind][shard] ??= {};
      shards[kind][shard][slug] ??= [];
      shards[kind][shard][slug].push({
        id: r.id,
        title: r.title,
        severity: r.cvss?.rating || null,
        ranges,
        fixed: sw.patched_versions || [],
        link: "https://www.wordfence.com/threat-intel/vulnerabilities/id/" + r.id,
      });
      entries++;
    }
  }

  fs.rmSync("data", { recursive: true, force: true });
  for (const kind of ["plugins", "themes"]) {
    fs.mkdirSync("data/" + kind, { recursive: true });
    for (const [shard, content] of Object.entries(shards[kind])) {
      fs.writeFileSync("data/" + kind + "/" + shard + ".json", JSON.stringify(content));
    }
  }

  // Aviso de direitos de autor exigido pelos termos da Wordfence Intelligence.
  fs.writeFileSync(
    "data/meta.json",
    JSON.stringify(
      {
        generated: new Date().toISOString(),
        records: records.length,
        entries,
        source: "Wordfence Intelligence (https://www.wordfence.com/threat-intel/)",
        copyrights: [...notices.values()],
      },
      null,
      2
    )
  );
  console.log("Feito! " + entries + " entradas guardadas em data/.");
}

// O feed pode vir em vários formatos. Aceitamos todos.
function parseRecords(text) {
  try {
    const data = JSON.parse(text);
    if (Array.isArray(data)) return data;
    if (Array.isArray(data.data)) return data.data;
    if (Array.isArray(data.vulnerabilities)) return data.vulnerabilities;
    return Object.values(data).filter((v) => v && typeof v === "object");
  } catch {
    // Formato "uma linha, um registo" (NDJSON)
    return text
      .split("\n")
      .filter((line) => line.trim())
      .map((line) => JSON.parse(line));
  }
}

function shardOf(slug) {
  const c = slug[0];
  return /[a-z0-9]/.test(c) ? c : "_";
}
