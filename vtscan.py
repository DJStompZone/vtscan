import time
import os
import argparse

import vt


class VTScan:
    def __init__(self, apikey: str):
        self.apikey = apikey
        self.client = vt.Client(apikey)

    def scan_file(
        self,
        file_path: str,
        wait: bool = False,
    ) -> vt.Object:
        """
        Scan a file with VirusTotal
        """
        if not os.path.isfile(file_path):
            raise ValueError("File does not exist")
        with open(file_path, "rb") as f, self.client as client:
            scan: vt.object.Object = client.scan_file(f, wait_for_completion=wait)
        return scan

    def wait_for_file_report(
        self, scan: vt.object.Object, debug=False
    ) -> vt.object.Object:
        """
        Wait for the analysis to complete
        Warning: Buggy (Unclosed client session)
        Todo: Fix
        """
        elapsed = 0
        interval: int = 10
        with self.client as client:
            analysis: vt.object.Object = client.get_object(f"/analyses/{scan.id}")
            while elapsed <= 120 and analysis.status != "completed":
                if elapsed > 0:
                    analysis: vt.object.Object = client.get_object(
                        f"/analyses/{scan.id}"
                    )
                if debug:
                    print("Debug - Analysis status:", analysis.status)
                    print("Debug - Elapsed:", f"{elapsed}s")
                time.sleep(interval)
                elapsed += interval
            if analysis.status != "completed":
                raise TimeoutError("Analysis timed out for scan: {scan.id}")
            return analysis

    def get_results(self, analysis: vt.object.Object) -> vt.object.WhistleBlowerDict:
        """
        Get the results of the analysis
        """
        if type(analysis.results) is vt.object.WhistleBlowerDict:
            return analysis.results
        raise ValueError("Invalid analysis type")

    def check_results(
        self, report: dict | vt.object.WhistleBlowerDict | vt.object.Object
    ) -> list[str]:
        """
        Check the results of the analysis
        """

        def _get_hits(r: dict) -> list[str]:
            return [r[ea] for ea in r.keys() if r[ea]["result"] is not None]

        if type(report) is vt.object.Object:
            results = report.to_dict()["attributes"]["results"]
            return _get_hits(results)

        elif type(report) is vt.object.WhistleBlowerDict:
            return _get_hits(report)

        elif (
            type(report) is dict
            and "attributes" in report.keys()
            and "results" in report["attributes"].keys()
        ):
            return _get_hits(report["attributes"]["results"])

        raise ValueError("Invalid report type")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("-f", "--file", help="File to scan")
    parser.add_argument("-k", "--apikey", help="VirusTotal API key")
    args: argparse.Namespace = parser.parse_args()

    apikey: str | None = args.apikey or os.getenv("VT_API_KEY")

    if apikey is None:
        print("No API key provided")
        exit(code=1)

    if not args.file:
        print("No file provided")
        exit(code=2)

    vtscan = VTScan(apikey=apikey)
    scan = vtscan.scan_file(file_path=args.file, wait=True)

    if scan is None:
        print("Something went wrong")
        exit(code=3)

    scan: vt.object.Object = vtscan.wait_for_file_report(scan, debug=True)
    results: vt.object.WhistleBlowerDict = vtscan.get_results(scan)
    print("\n", vtscan.check_results(results), "\n")
