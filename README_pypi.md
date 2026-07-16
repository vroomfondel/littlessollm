# littlessollm — a little SSO for LiteLLM

WIP - not tested at all yet.


Minimal, **MIT-only**, config-driven OIDC UI-SSO + API-JWT auth add-on for
[LiteLLM](https://github.com/BerriAI/litellm). No `litellm_enterprise`
import, no license check bypassed — UI login and API auth run entirely on
your own code, on top of litellm's MIT core.

```bash
pip install littlessollm
littlessollm-entrypoint uvicorn littlessollm.asgi:app --host 0.0.0.0 --port 4000
```

Status: alpha — the auth modules (UI-SSO router, API-JWT→virtual-key
middleware, YAML config/secrets loader, entrypoint wrapper) are
implemented and unit-tested.

Project home: <https://github.com/vroomfondel/littlessollm>

---

**Disclaimer:** Not an official LiteLLM/BerriAI project, no
affiliation/endorsement implied. Relies on litellm-internal, non-stable
APIs (see the README on GitHub) and is security-critical auth code —
review it yourself before production use. Provided "AS IS" without
warranty (MIT license).

## License

This project is licensed under the MIT license where applicable/possible — see [LICENSE.md](LICENSE.md). Some files/parts may use other licenses: [MIT](LICENSEMIT.md) | [GPL](LICENSEGPL.md) | [LGPL](LICENSELGPL.md). Always check per‑file headers/comments.


## Authors
- Repo owner (primary author)
- Additional attributions are noted inline in code comments


## Acknowledgments
- Inspirations and snippets are referenced in code comments where appropriate.


## ⚠️ Note

This is a development/experimental project. For production use, review security settings, customize configurations, and test thoroughly in your environment. Provided "as is" without warranty of any kind, express or implied, including but not limited to the warranties of merchantability, fitness for a particular purpose and noninfringement. In no event shall the authors or copyright holders be liable for any claim, damages or other liability, whether in an action of contract, tort or otherwise, arising from, out of or in connection with the software or the use or other dealings in the software. Use at your own risk.
