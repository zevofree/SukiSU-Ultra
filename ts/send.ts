import { Bot, InlineKeyboard } from "grammy";
import { z } from "zod";

const EnvSchema = z.object({
  BOT_TOKEN: z.string(),
  TELEGRAM_GROUP_ID: z.string(),
  TELEGRAM_TOPIC_COMMITS: z.string(),
  TELEGRAM_TOPIC_PRS: z.string(),
  GITHUB_TOKEN: z.string(),
  GITHUB_EVENT_PATH: z.string(),
});
const env = EnvSchema.parse(process.env);

const bot = new Bot(env.BOT_TOKEN);

const PullRequestSchema = z.object({
  action: z.string(),
  number: z.number(),
  repository: z.object({
    full_name: z.string(),
    html_url: z.url(),
  }),
  pull_request: z.object({
    url: z.url(),
    title: z.string(),
    body: z.string().nullable(),
    user: z.object({
      login: z.string(),
      html_url: z.url(),
    }),
    head: z.object({ ref: z.string() }),
    base: z.object({ ref: z.string() }),
    changed_files: z.number(),
    additions: z.number(),
    deletions: z.number(),
  }),
});

const PushSchema = z.object({
  ref: z.string(),
  repository: z.object({
    full_name: z.string(),
    html_url: z.url(),
  }),
  head_commit: z
    .object({
      id: z.string(),
      url: z.url(),
      message: z.string(),
      author: z.object({
        name: z.string(),
        email: z.email(),
      }),
      added: z.array(z.string()),
      modified: z.array(z.string()),
      removed: z.array(z.string()),
    })
    .nullable(),
});

function detectLanguage(files: string[]): string {
  const extCount = files.reduce<Record<string, number>>((count, file) => {
    const ext = file.split(".").pop()?.toLowerCase() ?? "";
    count[ext] = (count[ext] || 0) + 1;
    return count;
  }, {});
  if (extCount.kt || extCount.kts) return "Kotlin";
  if (extCount.c && !extCount.h) return "C";
  if (extCount.rs) return "Rust";
  if (extCount.sh) return "Shell";
  if (extCount.ts || extCount.tsx) return "TypeScript";
  return "Unknown";
}

interface GitHubPRFilesResponse {
  data: {
    repository: {
      pullRequest: {
        files: {
          nodes: { path: string }[];
        };
      };
    };
  };
}

async function fetchPrFiles(
  repoFullName: string,
  prNumber: number,
): Promise<string[]> {
  const query = `
    query($owner: String!, $name: String!, $number: Int!) {
      repository(owner: $owner, name: $name) {
        pullRequest(number: $number) {
          files(first: 100) {
            nodes { path }
          }
        }
      }
    }`;
  const [owner, name] = repoFullName.split("/");
  const resp = await fetch("https://api.github.com/graphql", {
    method: "POST",
    headers: {
      Authorization: `bearer ${env.GITHUB_TOKEN}`,
      "Content-Type": "application/json",
    },
    body: JSON.stringify({
      query,
      variables: { owner, name, number: prNumber },
    }),
  });
  if (!resp.ok) {
    throw new Error(`GitHub API error: ${resp.status} ${resp.statusText}`);
  }
  const json = (await resp.json()) as GitHubPRFilesResponse;
  if (!json?.data?.repository?.pullRequest?.files?.nodes) return [];
  return json.data.repository.pullRequest.files.nodes.map((n) => n.path);
}

async function formatPrMessage(
  evt: z.infer<typeof PullRequestSchema>,
): Promise<string> {
  const files = await fetchPrFiles(evt.repository.full_name, evt.number);
  const lang = detectLanguage(files);
  return `Repository: [${evt.repository.full_name}](${evt.repository.html_url})
Pull Request #: [${evt.number}](${evt.pull_request.url})
Author: [${evt.pull_request.user.login}](${evt.pull_request.user.html_url})
Files Changed: ${evt.pull_request.changed_files}, +${evt.pull_request.additions}/- ${evt.pull_request.deletions}
Likely Language: ${lang}
Title: ${evt.pull_request.title}
Description: ${evt.pull_request.body ?? "_None provided_"}`;
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
    c.removed.length ? `Removed: ${c.removed.join(", ")}` : "",
  ]
    .filter(Boolean)
    .join("\n");
  const lang = detectLanguage([...c.added, ...c.modified, ...c.removed]);
  return `Repository: [${evt.repository.full_name}](${evt.repository.html_url})
Commit: [${c.id}](${c.url})
Author: ${c.author.name} <${c.author.email}>
Message: ${c.message}
${details ? details + "\n" : ""}Detected Language: ${lang}`;
}

async function main(): Promise<void> {
  try {
    const raw = await Bun.file(env.GITHUB_EVENT_PATH).text();
    const parsed = JSON.parse(raw);

    let message: string;
    let topic: number;

    const prResult = PullRequestSchema.safeParse(parsed);
    if (prResult.success) {
      message = await formatPrMessage(prResult.data);
      topic = Number(env.TELEGRAM_TOPIC_PRS);
    } else {
      const pushResult = PushSchema.safeParse(parsed);
      if (!pushResult.success) {
        console.error(
          "Unrecognized event payload",
          prResult.error,
          pushResult.error,
        );
        process.exit(1);
      }
      message = formatPushMessage(pushResult.data);
      topic = Number(env.TELEGRAM_TOPIC_COMMITS);
    }

    const keyboard = new InlineKeyboard().url(
      "View on GitHub",
      (parsed.repository as any).html_url as string,
    );
    await bot.api.sendMessage(Number(env.TELEGRAM_GROUP_ID), message, {
      parse_mode: "Markdown",
      message_thread_id: topic,
      reply_markup: keyboard,
    });

    process.exit(0);
  } catch (err) {
    console.error("Fatal error in main execution:", err);
    process.exit(1);
  }
}

void main();
