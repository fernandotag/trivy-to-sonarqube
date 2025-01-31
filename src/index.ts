import { promises as fs } from 'fs';
import path from 'path';

import { SonarReport, SonarRule, TrivyReport, TrivySeverity } from './interfaces';
const ENGINE_ID = 'Trivy'
const VULNERABILITY = 'VULNERABILITY'

/**
 * Convert Severity trivy to sonarqube
 * @param {string} level
 * @returns {SonarRule["severity"]}
 */
function convertSeverity(level: TrivySeverity): SonarRule['severity'] {
  switch (level) {
    case 'HIGH':
      return 'BLOCKER';
    case 'LOW':
      return 'MINOR';
    case 'CRITICAL':
      return 'CRITICAL';
    case 'MEDIUM':
      return 'MAJOR';
    default:
      return 'INFO';
  }
}

export async function convertReport(inputFile: string, outputFile: string): Promise<void> {
  const reportBlob = await fs.readFile(path.join(inputFile));
  const report: TrivyReport | undefined = JSON.parse(reportBlob.toString() || '{}');
  const data: SonarReport = { rules: [], issues: [] }

  for (const file of report?.Results || []) {
    for (const issue of file?.Misconfigurations || []) {

      if (!data.rules.some(rule => rule.id === issue.AVDID)) {
        data.rules.push({
          id: issue.AVDID,
          name: issue.Title,
          engineId: ENGINE_ID,
          type: VULNERABILITY,
          description: `<p>${issue.Description}</p><p><b>Resolution:</b> ${issue.Resolution}</p><p><b>Details:</b> (${issue.PrimaryURL})</p>`,
          cleanCodeAttribute: "TRUSTWORTHY",
          severity: convertSeverity(issue.Severity),
        });
      }

      data.issues.push({
        engineId: ENGINE_ID,
        ruleId: issue.AVDID,
        primaryLocation: {
          filePath: file.Target,
          message: `${issue.Message}`,
        }
      });

    }

    // if exists
    for (const issue of file?.Vulnerabilities || []) {
      if (!data.rules.some(rule => rule.id === issue.VulnerabilityID)) {
        data.rules.push({
          id: issue.VulnerabilityID,
          name: issue.Title,
          engineId: ENGINE_ID,
          type: VULNERABILITY,
          description: issue.FixedVersion ?
            `<p>${issue.Description}</p><p><b>FixedVersion:</b> ${issue.FixedVersion}</p><p><b>Details:</b> ${issue.PrimaryURL}</p>` :
            `<p>${issue.Description}</p><b>FixedVersion:</b>Incomplete fix</p><p><b>Details:</b> ${issue.PrimaryURL}</p>`,
          cleanCodeAttribute: "TRUSTWORTHY",
          severity: convertSeverity(issue.Severity),
        });
      }

      data.issues.push({
        engineId: ENGINE_ID,
        ruleId: issue.VulnerabilityID,
        primaryLocation: {
          filePath: file.Target,
          message: issue.FixedVersion ?
            `Upgrade dependency ${issue.PkgName} from ${issue.InstalledVersion} to ${issue.FixedVersion}` :
            `Upgrade dependency ${issue.PkgName} from ${issue.InstalledVersion} to the latest version`,
        }
      });
    }
  }
  await fs.writeFile(path.join(outputFile), JSON.stringify(data, null, 2), {
    flag: 'w',
  });


}
