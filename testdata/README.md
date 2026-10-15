# Test data and Postman

5,000 synthetic outcomes for about 1,200 made-up customers (70% Pakistan, 30% UAE), plus 500 customers to check and a set of bad rows for validation tests. Every `order_ref` starts with `TEST-`.

| File | Use it for |
| --- | --- |
| `out/outcomes_part1.csv` … `part5.csv` | Web app → Enter outcomes → Upload in bulk (1,000 rows per upload) |
| `out/outcomes_batch1.json` … `batch5.json` | `POST /v1/events/batch` (1,000 each) |
| `out/outcomes_all.csv` | Postman Collection Runner data file (folder 13) |
| `out/checks_500.csv` / `.json` | Web app → Check orders → Check many, or `POST /v1/check/batch` |
| `out/invalid_rows.csv` / `.json` | 14 rows a batch must reject one by one |
| `out/invalid_schema.json` | 9 bodies that must each get HTTP 422 |
| `out/customers.csv` | The profile each test customer was generated with (good, occasional, serial refuser, fraudster, return abuser) |

**See high-risk results.** A customer reported by only one store is capped at medium. Upload parts 1–2 as one store and parts 3–5 as another.

## Safe ways to load it

The phone numbers are synthetic but valid-looking, so one could belong to a real person. Load them in one of these ways:

1. **Sandbox:** use a `cs_test_` key. Everything is validated and nothing is stored.
2. **Local:** run the app on your PC with SQLite, or point it at a Neon test branch.
3. **Live, then purge:** load into the live site to demo it, then remove it:

```
python -m codshield.testdata count
python -m codshield.testdata purge
```

## Commands

```
python testdata/generate.py                                    # rebuild the files (same output every time)
python testdata/upload.py --key cs_test_...                    # 5 batches + 500 checks through the API
python testdata/upload.py --key cs_live_A... --key2 cs_live_B...  # two stores, so high-risk results appear
python tools/postman/build.py                                  # rebuild the Postman collection (docs/postman/)
```

## Postman

Import `docs/postman/CODShield.postman_collection.json` and `docs/postman/CODShield-Live.postman_environment.json` (or `-Local`), then select the environment. In the environment, fill in:

- `adminKey`
- `newPassword` (10+ characters)
- `adminEmail` / `adminPassword`, only on an empty system

Run folders 01–12 in the Collection Runner. Each request saves the keys and IDs the next one needs. Folder 13 runs on its own with `out/outcomes_all.csv` as the data file.

The same requests also exist as a git-native Postman v3 collection in `postman/collections/CODShield API/`, with 88 saved example responses. The Postman CLI and Postman's Git sync read that format; the OpenAPI spec is in `postman/specs/`. Rebuild it after an API change with `tools/postman/build_v3.py` (see the steps at the top of that file).
