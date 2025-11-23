import { Bot, InlineKeyboard } from "grammy";
import { z } from "zod";

const BOT_TOKEN = process.env.BOT_TOKEN!;
const GROUP_ID = Number(process.env.TELEGRAM_GROUP_ID!);
const TOPIC_COMMITS = Number(process.env.TELEGRAM_TOPIC_COMMITS!);
const TOPIC_PRS = Number(process.env.TELEGRAM_TOPIC_PRS!);
const GITHUB_TOKEN = process.env.GITHUB_TOKEN!;
const EVENT_PATH = process.env.GITHUB_EVENT_PATH!;

const bot = new Bot(BOT_TOKEN);

const FileSchema = z.object({
  path: z.string(),
});

const PullRequestSchema = z.object({
  action: z.string(),
  number: z.number(),
  repository: z.object({
    full_name: z.string(),
    html_url: z.url()
  }),
  pull_request: z.object({
    url: z.url(),
    title: z.string(),
    body: z.string().nullable(),
    user: z.object({
      login: z.string(),
      html_url: z.url()
    }),
    head: z.object({ ref: z.string() }),
    base: z.object({ ref: z.string() }),
    changed_files: z.number(),
    additions: z.number(),
    deletions: z.number()
  })
});

const PushSchema = z.object({
  ref: z.string(),
  repository: z.object({
    full_name: z.string(),
    html_url: z.url()
  }),
  head_commit: z.object({
    id: z.string(),
    url: z.url(),
    message: z.string(),
    author: z.object({
      name: z.string(),
      email: z.email()
    }),
    added: z.array(z.string()),
    modified: z.array(z.string()),
    removed: z.array(z.string())
  }).nullable()
});

function detectLanguage(files: string[]): string {
  const ext = files.map(f => f.split(".").pop()?.toLowerCase() || "");
  if (ext.includes("kt") || ext.includes("kts")) return "Kotlin";
  if (ext.includes("c") && !ext.includes("h")) return "C";
  if (ext.includes("rs")) return "Rust";
  if (ext.includes("sh")) return "Shell";
  if (ext.includes("ts") || ext.includes("tsx")) return "TypeScript";
  return "Unknown";
}

async function fetchPrFiles(repoFullName: string, prNumber: number): Promise<string[]> {
  const query = `
    query($owner: String!, $name: String!, $number: Int!) {
      repository(owner: $owner, name: $name) {
        pullRequest(number: $number) {
          files(first: 100) {
            nodes {
              path
            }
          }
        }
      }
    }`;
  const [owner, name] = repoFullName.split("/");
  const resp = await fetch("https://api.github.com/graphql", {
    method: "POST",
    headers: {
      "Authorization": `bearer ${GITHUB_TOKEN}`,
      "Content-Type": "application/json"
    },
    body: JSON.stringify({ query, variables: { owner, name, number: prNumber } })
  });
  const json = await resp.json() as any;
  const nodes = json.data.repository.pullRequest.files.nodes as { path: string }[];
  return nodes.map(n => n.path);
}

async function formatPrMessage(evt: z.infer<typeof PullRequestSchema>): Promise<string> {
  const files = await fetchPrFiles(evt.repository.full_name, evt.number);
  const lang = detectLanguage(files);
  return `Repository: [${evt.repository.full_name}](${evt.repository.html_url})
Pull Request #: [${evt.number}](${evt.pull_request.url})
Author: [${evt.pull_request.user.login}](${evt.pull_request.user.html_url})
Files Changed: ${evt.pull_request.changed_files}, +${evt.pull_request.additions}/- ${evt.pull_request.deletions}
Likely Language: ${lang}
Title: ${evt.pull_request.title}
Description: ${evt.pull_request.body ?? "_None provided_"}`
}

function formatPushMessage(evt: z.infer<typeof PushSchema>): string {
  const c = evt.head_commit;
  if (!c) {
    return `Repository: [${evt.repository.full_name}](${evt.repository.html_url})
Push event but no head commit data.`;
  }
  const details = [
    c.added.length ? `Added: ${c.added.join(", ")}` : "",
    c.modified.length ? `Modified: ${c.modified.join(", ")}` : "",
    c.removed.length ? `Removed: ${c.removed.join(", ")}` : ""
  ].filter(Boolean).join("\n");
  const lang = detectLanguage([...c.added, ...c.modified, ...c.removed]);
  return `Repository: [${evt.repository.full_name}](${evt.repository.html_url})
Commit: [${c.id}](${c.url})
Author: ${c.author.name} <${c.author.email}>
Message: ${c.message}
${details ? details + "\n" : ""}Detected Language: ${lang}`;
}

async function main(): Promise<void> {
  const raw = await (await import("node:fs/promises")).readFile(EVENT_PATH, "utf-8");
  const parsed = JSON.parse(raw);
  let message: string;
  let topic: number;

  try {
    const prEvt = PullRequestSchema.parse(parsed);
    message = await formatPrMessage(prEvt);
    topic = TOPIC_PRS;
  } catch {
    const pushEvt = PushSchema.parse(parsed);
    message = formatPushMessage(pushEvt);
    topic = TOPIC_COMMITS;
  }

  const keyboard = new InlineKeyboard().url("View on GitHub", (parsed.repository as any).html_url as string);
  await bot.api.sendMessage(GROUP_ID, message, {
    parse_mode: "Markdown",
    message_thread_id: topic,
    reply_markup: keyboard
  });

  process.exit(0);
}

main().catch(err => {
  console.error(err);
  process.exit(1);
});
