import requests
from utils.output import section, info, success, warning, error, result, table

GITHUB_API = "https://api.github.com"


def github_request(endpoint, timeout=15):
    url = f"{GITHUB_API}/{endpoint.lstrip('/')}"
    try:
        resp = requests.get(
            url, timeout=timeout,
            headers={
                "User-Agent": "Reconnor-OSINT/1.0",
                "Accept": "application/vnd.github.v3+json",
            },
        )
        if resp.status_code == 200:
            return resp.json()
        elif resp.status_code == 403:
            warning("GitHub API rate limit exceeded (60/hr without token)")
            return None
        elif resp.status_code == 404:
            return {"_notfound": True}
        return None
    except Exception as e:
        error(f"GitHub API error: {e}")
        return None


def search_github_code(query, timeout=15):
    try:
        resp = requests.get(
            f"https://api.github.com/search/code?q={query}",
            timeout=timeout,
            headers={
                "User-Agent": "Reconnor-OSINT/1.0",
                "Accept": "application/vnd.github.v3+json",
            },
        )
        if resp.status_code == 200:
            return resp.json().get("items", [])[:15]
        return None
    except:
        return None


def search_github_repos(query, timeout=15):
    try:
        resp = requests.get(
            f"https://api.github.com/search/repositories?q={query}&sort=stars&order=desc",
            timeout=timeout,
            headers={
                "User-Agent": "Reconnor-OSINT/1.0",
                "Accept": "application/vnd.github.v3+json",
            },
        )
        if resp.status_code == 200:
            return resp.json().get("items", [])[:15]
        return None
    except:
        return None


class GitHubOSINT:
    name = "github"
    description = "GitHub user, repository, and code OSINT"

    @staticmethod
    def run(target, mode="user"):
        section(f"GitHub OSINT: {target}")

        if mode == "user":
            info(f"Fetching user profile: {target}")
            user = github_request(f"users/{target}")
            if user is None:
                warning("Could not fetch user data (rate limited?)")
                return {"target": target, "error": "API limit or not found"}
            if user.get("_notfound"):
                error(f"GitHub user '{target}' not found")
                return {"target": target, "error": "User not found"}

            result("Login", user.get("login", ""))
            result("Name", user.get("name", "N/A"))
            result("Bio", user.get("bio", "N/A")[:100] if user.get("bio") else "N/A")
            result("Company", user.get("company", "N/A"))
            result("Location", user.get("location", "N/A"))
            result("Email", user.get("email", "N/A"))
            result("Blog", user.get("blog", "N/A"))
            result("Twitter", user.get("twitter_username", "N/A"))
            result("Followers", str(user.get("followers", 0)))
            result("Following", str(user.get("following", 0)))
            result("Public Repos", str(user.get("public_repos", 0)))
            result("Public Gists", str(user.get("public_gists", 0)))
            result("Created", user.get("created_at", "N/A"))
            result("Updated", user.get("updated_at", "N/A"))
            result("Hireable", str(user.get("hireable", "N/A")))
            result("Type", user.get("type", "N/A"))
            result("Profile URL", user.get("html_url", ""))

            section(f"Repositories ({user.get('public_repos', 0)})")
            repos = github_request(f"users/{target}/repos?per_page=30&sort=updated")
            if repos and not isinstance(repos, dict):
                for repo in repos[:15]:
                    name = repo.get("name", "")
                    desc = repo.get("description", "") or ""
                    stars = repo.get("stargazers_count", 0)
                    forks = repo.get("forks_count", 0)
                    lang = repo.get("language", "?")
                    private = " [PRIVATE]" if repo.get("private") else ""
                    success(f"  {name}{private} ({lang}, ★{stars}, ⑂{forks})")
                    if desc:
                        info(f"    {desc[:120]}")

            section("Contributions (recent)")
            events = github_request(f"users/{target}/events?per_page=5")
            if events and not isinstance(events, dict):
                for event in events[:5]:
                    et = event.get("type", "")
                    repo_name = event.get("repo", {}).get("name", "")
                    created = event.get("created_at", "")[:10]
                    info(f"  [{created}] {et} in {repo_name}")

        elif mode == "repo":
            info(f"Fetching repository: {target}")
            if "/" not in target:
                warning(f"Repository '{target}' not found — expected format 'owner/repo' (e.g., 'tensorflow/tensorflow')")
                warning("Try: python3 main.py github tensorflow --mode search")
                return {"target": target, "error": "Invalid format. Use owner/repo (e.g., tensorflow/tensorflow)"}
            repo = github_request(f"repos/{target}")
            if repo is None:
                warning("Could not fetch repo data (rate limited?)")
                return {"target": target, "error": "API limit"}
            if repo.get("_notfound"):
                error(f"Repository '{target}' not found")
                return {"target": target, "error": "Repo not found"}

            result("Full Name", repo.get("full_name", ""))
            result("Description", (repo.get("description") or "N/A")[:150])
            result("Stars", str(repo.get("stargazers_count", 0)))
            result("Forks", str(repo.get("forks_count", 0)))
            result("Watchers", str(repo.get("subscribers_count", 0)))
            result("Open Issues", str(repo.get("open_issues_count", 0)))
            result("Language", repo.get("language", "N/A"))
            result("License", repo.get("license", {}).get("spdx_id", "N/A") if repo.get("license") else "N/A")
            result("Topics", ", ".join(repo.get("topics", [])[:10]) or "N/A")
            result("Default Branch", repo.get("default_branch", "N/A"))
            result("Created", repo.get("created_at", "N/A"))
            result("Updated", repo.get("updated_at", "N/A"))
            result("Archived", str(repo.get("archived", False)))
            result("URL", repo.get("html_url", ""))

            if repo.get("parent"):
                section("Forked From")
                parent = repo["parent"]
                result("Parent", parent.get("full_name", ""))
                result("Parent Stars", str(parent.get("stargazers_count", 0)))

            section("Recent Commits")
            commits = github_request(f"repos/{target}/commits?per_page=5")
            if commits and not isinstance(commits, dict):
                for commit in commits[:5]:
                    sha = commit.get("sha", "")[:8]
                    msg = commit.get("commit", {}).get("message", "").split("\n")[0]
                    author = commit.get("commit", {}).get("author", {}).get("name", "")
                    info(f"  {sha} - {msg[:80]} ({author})")

        elif mode == "search":
            info(f"Searching GitHub for: {target}")
            repos = search_github_repos(target)
            if repos:
                section(f"Top Repositories matching '{target}'")
                for repo in repos:
                    name = repo.get("full_name", "")
                    desc = (repo.get("description") or "")[:100]
                    stars = repo.get("stargazers_count", 0)
                    lang = repo.get("language", "?")
                    result(f"★{stars}", f"{name} [{lang}] - {desc}")

            code_results = search_github_code(target)
            if code_results:
                section(f"Code matches for '{target}'")
                for item in code_results[:10]:
                    path = item.get("path", "")
                    repo_name = item.get("repository", {}).get("full_name", "")
                    result(repo_name, path)

        return {"target": target, "mode": mode}
