# Disclosure policy for ecosystem studies

RLS Doctor's ecosystem studies analyze **public source code** (SQL migration
files) statically and offline. They never connect to a live database, never
run probes, and never exploit anything.

## What we publish

- **Aggregate, anonymized statistics only.** Percentages, counts, and rule
  breakdowns across the sample.
- **No repository names, owners, or links.** A finding that would identify a
  specific project is not published, even as an example, unless the
  maintainers explicitly agree.
- **Methodology and limitations.** Sample construction, tool versions, exact
  commands, and what static analysis cannot prove.

## What we do not do

- No live database access, no credential use, no exploitation.
- No individual notifications built on unnamed findings. If a study ever
  surfaces something that appears to be a real, exploitable exposure, we
  stop and handle it through coordinated disclosure first: contact the
  maintainers privately, wait for a fix or a documented decision, and only
  then decide whether any aggregate statement is still warranted.

## Limitations we state up front

- Static analysis proves patterns in migrations, not runtime behavior.
  A repo can have a risky pattern and a safe runtime configuration, or vice
  versa.
- Parser coverage is bounded: unsupported statements become coverage
  limitations, and those are counted in the results.
- Samples are convenience samples (for example, "repositories returned by a
  GitHub search"), not random samples. We say so.

## Corrections

If you maintain a project and believe a published aggregate is wrong or
misleading, open an issue or email **subhajitpradhan310@gmail.com**. We will
correct or retract promptly.
