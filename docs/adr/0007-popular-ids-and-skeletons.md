# 0007: Which IDs are popular, and how IDs are compared

Status: accepted, 2026-11-25

## Context

Rules C402 and C403 compare a package ID with a list of popular IDs. The design planned the list as the 4,000 most downloaded IDs from the nuget.org search API, and the comparison as "the skeleton of the ID equals the skeleton of a popular ID" for C402 and "one edit, or only separators, on lowercase forms" for C403. Building it on 2026-11-25 showed four problems with that plan.

1. **The search API's empty query leaves out popular packages.** An empty query is nuget.org's "default search", and it filters out the packages on nuget.org's list of packages excluded by default (`SearchParametersBuilder.cs` and `NewPackageRegistrationFromDbProducer.cs` in NuGet.Services.AzureSearch, read 2026-11-25). xunit.core, with 1,219,685,340 downloads, and Microsoft.Data.Edm are among them. Without them, a scan of a local cache reported xunit.core as one edit from TUnit.Core, which would warn every project that uses xUnit v2.
2. **The target of the 2024 campaign is not popular.** Guna.UI2.WinForms had 771,550 downloads on 2026-11-25; the 4,000th ID of the default search had 6,484,229. A list of the most downloaded IDs cannot hold it, so the exit test's look-alike of it would pass.
3. **The case of an ID in a lock file is not reliable.** NuGet compares IDs ignoring case, and a lock file can hold an ID in any case. UTS #39 skeletons keep case, so `gսոa.ui2.winforms` and `Guna.UI2.WinForms` have different skeletons.
4. **The published campaign ID is not a pure look-alike.** `Gսոa.UI3.Wіnfօrms` also changed `UI2` to `UI3`. Its skeleton is one edit from the skeleton of `Guna.UI2.WinForms`, and its lowercase form is five edits from it, so C403 on lowercase forms misses it.

## Decision

- **The popular list** (`data/popular-ids.txt`, made by `data/popular.py`) is the 4,000 IDs of the default search by total downloads, plus every ID with at least as many downloads as the least downloaded of those that a search by owner finds for one of their owners. A search by owner is not a default search, so it reaches the excluded packages of owners that have a popular package.
- **Targeted IDs** (`data/targeted-ids.txt`) are added by hand: an ID that a public write-up says a campaign imitated, with the source on its line. It holds Guna.UI2.WinForms.
- **Skeletons of lowercase forms.** An ID is lowercased as NuGet lowercases it, mapped to its skeleton, and lowercased again. The second lowercasing makes a digit that the skeleton maps to a capital letter (`0` to `O`) equal to the lowercase letter, so `Newtonsoft.Js0n` is a look-alike.
- **C402** is an equal skeleton; **C403** is one edit between skeletons, or skeletons equal once separators are removed, for IDs of at least six characters. For an ASCII ID without confusable characters the skeleton is the lowercase form, so this is what the design planned; for an ID with confusable characters it catches the campaign ID above.
- **A popular ID is exempt** from C402 and C403: it is what a look-alike imitates. The pairs of popular IDs that resemble each other are listed with a reason in `data/popular-pairs.txt`, and a test fails on a pair that is not listed and on a listed pair it no longer finds.

## Consequences

- The list is larger than 4,000 and its size changes when it is made again; the header of the file says how many came from each step.
- An ID of the long tail that a campaign imitates is protected only once someone adds it to the targeted list. C401 still reports any ID with non-ASCII letters, whatever it imitates.
- Families of related IDs (`runtime.<distribution>.<version>-x64...`, `Humanizer.Core.<language>`) are one edit apart from each other. A member of such a family that is not itself popular is a C403 warning; the corpus and the local cache measure how often (see the M4 entry of the roadmap).
- Tests: `the_armenian_look_alike_of_guna_is_c401_and_c402`, `the_published_campaign_id_is_c401_and_one_edit_from_guna`, `a_digit_in_place_of_a_letter_is_a_look_alike` and `no_popular_id_resembles_another_outside_the_reviewed_pairs` in `src/names.rs`.
