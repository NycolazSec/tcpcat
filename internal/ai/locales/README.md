# Translating tcpcat's AI

tcpcat's AI explains every open port: what the service is, why it matters,
and how to fix it. It speaks English and French. Each other language is one
file in this directory, and you can write one without knowing Go.

## Add your language from your browser

1. Open [`TEMPLATE.yaml`](TEMPLATE.yaml) and copy its content (the "Copy raw
   file" button).
2. In this directory, choose **Add file → Create new file**. Name the file
   after your language's code: `es.yaml`, `de.yaml`, `pt-BR.yaml`, `zh-CN.yaml`,
   and so on. Paste the template.
3. Fill in `name` (your language's name, written in your language), `decimal`,
   `thousands` and `percent`, then translate the texts between the quotes.
   Above each text, a comment shows the English (`en:`) and the French (`fr:`).
4. Choose **Commit changes… → Create a new branch and start a pull request**.

A partial translation is welcome: any text left empty (`""`) is shown in
English. CI checks the file and says what to fix, if anything.

## The rules

- **Keep the placeholders.** `%d`, `%s`, `%.0f` and the like are replaced by
  numbers and names. You can move them in the sentence; to change their order,
  number them: `%[2]s` is the second one. Write `%%` for a percent sign.
- **In `phrases`, keep the left side as it is.** It is the English text that
  tcpcat looks up; translate the right side only.
- **Write what you would tell a colleague.** The AI addresses system
  administrators: plain, precise, no jargon that a native speaker would not
  use. Commands, file names and settings (`sshd_config`,
  `PasswordAuthentication no`) stay as they are.
- **Ask a native speaker to read it**, if you can. A review in the pull
  request is as valuable as the translation.

## With Go installed

From the repository root:

```bash
go run ./internal/ai/localetool status        # how much of each language is done
go run ./internal/ai/localetool template es   # es.yaml with what is still missing
go run ./internal/ai/localetool check         # the checks CI runs
go build -o /tmp/tcpcat ./cmd/tcpcat && /tmp/tcpcat ai model --lang es
```

tcpcat picks the language from `--ai-lang` (on a scan), `--lang` (for
`tcpcat ai`), or `$LANG`. `es_MX.UTF-8`, for example, selects `es`.

## What stays in English for now

The template covers what the AI concludes and the command line's own words.
These parts are still written in English (or French) only:

- the dictionary's description of each service (`internal/ai/kb/services.yaml`);
- the scanner's own wording, which the AI quotes ("SYN-ACK received");
- the help of `tcpcat ai`.

Pull requests that make them translatable too are welcome.

## When the English changes

When a sentence is added or changed in tcpcat, `TEMPLATE.yaml` is regenerated
(`go run ./internal/ai/localetool template > internal/ai/locales/TEMPLATE.yaml`)
and CI fails until it is. The history of `TEMPLATE.yaml` therefore shows every
change to translate.

- When the English of a **phrase** changes, `check` reports the old one, and
  tcpcat shows the English until the translation is updated.
- A **message** keeps its ID when its English is reworded, so its translation
  stays in use: check the history for such changes.
