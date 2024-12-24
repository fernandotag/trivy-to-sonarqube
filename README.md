This repository is a fork of the [Trivy-to-SonarQube](https://github.com/Blynskyniki/trivy-to-sonarqube) project, with improvements to the process of importing Trivy reports into SonarQube, including the creation of custom rules and enhanced visualization of vulnerabilities in SonarQube, making vulnerability analysis more user-friendly.

## Install

```bash
npm i trivy-to-sonarqube -g
```


## Generate trivy report 
```bash
trivy fs --ignorefile .trivyignore  -f json -o ./report/trivy-fs-report.json  .
trivy config --ignorefile .trivyignore  -f json -o ./report/trivy-config-report.json  .
trivy image --ignorefile .trivyignore  -f json -o ./report/trivy-image-report.json  my-docker-image


```

## Convert data to sonarqube generic issue format 

```bash 
trivy-to-sonarqube -f ./report/trivy-fs-report.json -o ./report/sonar-fs-report.json
trivy-to-sonarqube -f ./report/trivy-config-report.json -o ./report/sonar-config-report.json
trivy-to-sonarqube -f ./report/trivy-image-report.json -o ./report/sonar-image-report.json

```


## Run sonar-scaner witch additional params
```bash
 sonar-scanner 
      -Dsonar.projectKey=MyProject
      -Dsonar.host.url=my-host.com
      -Dsonar.login=${SONARQUBE_TOKEN}
      -Dsonar.sources=.
      -Dsonar.externalIssuesReportPaths=./report/sonar-fs-report.json,./report/sonar-config-report.json,./report/sonar-image-report.json

```
