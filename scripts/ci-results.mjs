export function parseTap(output) {
  const number = label => Number([...output.matchAll(new RegExp(`^# ${label} (\\d+)$`, 'gm'))].at(-1)?.[1] || 0);
  return { tests: number('tests'), passed: number('pass'), failed: number('fail') + number('cancelled'), skipped: number('skipped') + number('todo') };
}

export function parseJUnit(xml) {
  const suites = [...xml.matchAll(/<testsuite\b[^>]*>/g)].map(match => match[0]);
  const totals = { tests: 0, passed: 0, failed: 0, skipped: 0 };
  for (const suite of suites) {
    const value = key => Number(new RegExp(`\\b${key}="(\\d+)"`).exec(suite)?.[1] || 0);
    totals.tests += value('tests');
    totals.failed += value('failures') + value('errors');
    totals.skipped += value('skipped');
  }
  totals.passed = Math.max(0, totals.tests - totals.failed - totals.skipped);
  return totals;
}

export function suitePassed(exitCode, totals) {
  return exitCode === 0 && totals.tests > 0 && totals.failed === 0 && totals.skipped === 0;
}
