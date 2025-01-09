import argparse
import re
import pandas as pd
from rich.console import Console
from rich.table import Table
from datetime import datetime
import matplotlib.pyplot as plt
from jinja2 import Environment, FileSystemLoader
import os

class LogParser:
    def __init__(self, log_file):
        self.log_file = log_file
        self.regex = r"(\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2}) from (\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}):(\d+) (accepted|denied) tcp:([^:]+):(\d+)"

    def parse_line(self, line):
        match = re.match(self.regex, line)
        if match:
            return {
                "timestamp": match.group(1),
                "source_ip": match.group(2),
                "source_port": int(match.group(3)),
                "status": match.group(4),
                "destination_domain": match.group(5),
                "destination_port": int(match.group(6)),
            }
        return None

    def parse_log(self):
        parsed_lines = []
        with open(self.log_file, "r", encoding="utf-8") as f:
            for line in f:
                parsed_line = self.parse_line(line.strip())
                if parsed_line:
                    parsed_lines.append(parsed_line)
        return pd.DataFrame(parsed_lines)


class DataAnalyzer:
    def __init__(self, dataframe):
        self.df = dataframe

    def clean_data(self):
        # 处理缺失值或格式错误的数据
        self.df = self.df.dropna()
        self.df["timestamp"] = pd.to_datetime(self.df["timestamp"])
        return self.df

    def aggregate_data(self):
        # 进行数据聚合，返回聚合结果
        return self.df.groupby(["source_ip", "destination_domain", "status"]).size().reset_index(name="count")

    def calculate_statistics(self, top_n=10):
        # 计算统计指标，返回统计结果
        total_connections = self.df.shape[0]
        status_counts = self.df["status"].value_counts()
        top_source_ips = self.df["source_ip"].value_counts().nlargest(top_n)
        top_destination_domains = self.df["destination_domain"].value_counts().nlargest(top_n)
        return {
            "total_connections": total_connections,
            "status_counts": status_counts,
            "top_source_ips": top_source_ips,
            "top_destination_domains": top_destination_domains,
        }


class ReportGenerator:
    def __init__(self, analysis_results, log_file_path):
        self.results = analysis_results
        self.log_file_path = log_file_path
        self.console = Console()
        template_path = os.path.join(os.path.dirname(__file__), "report_template.html")
        self.env = Environment(loader=FileSystemLoader(os.path.dirname(template_path)))
        self.template = self.env.get_template(os.path.basename(template_path))

    def generate_html_report(self, output_path):
        # 生成HTML报告
        report_time = datetime.now().strftime("%Y/%m/%d %H:%M:%S")
        
        # Generate charts
        self.generate_charts()

        html = self.template.render(
            log_file_path=self.log_file_path,
            report_time=report_time,
            results=self.results,
        )
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(html)

    def generate_charts(self):
        # Generate Top Source IPs chart
        top_source_ips = self.results["top_source_ips"]
        if not top_source_ips.empty:
            plt.figure(figsize=(10, 6))
            plt.bar(top_source_ips.index, top_source_ips.values)
            plt.xlabel("IP Address")
            plt.ylabel("Count")
            plt.title("Top Source IPs")
            plt.xticks(rotation=45, ha="right")
            plt.tight_layout()
            plt.savefig("log_analyzer/top_source_ips.png")
            plt.close()

        # Generate Top Destination Domains chart
        top_destination_domains = self.results["top_destination_domains"]
        if not top_destination_domains.empty:
            plt.figure(figsize=(10, 6))
            plt.bar(top_destination_domains.index, top_destination_domains.values)
            plt.xlabel("Domain")
            plt.ylabel("Count")
            plt.title("Top Destination Domains")
            plt.xticks(rotation=45, ha="right")
            plt.tight_layout()
            plt.savefig("log_analyzer/top_destination_domains.png")
            plt.close()


    def generate_cli_report(self):
        # 生成CLI报告
        self.console.print(f"[bold blue]Log File:[/bold blue] {self.log_file_path}")
        self.console.print(f"[bold blue]Total Connections:[/bold blue] {self.results['total_connections']}")
        self.console.print("[bold blue]Connection Status:[/bold blue]")
        for status, count in self.results["status_counts"].items():
            self.console.print(f"  [green]{status}:[/green] {count}")

        self.console.print("[bold blue]Top Source IPs:[/bold blue]")
        table = Table(show_header=True, header_style="bold magenta")
        table.add_column("IP Address")
        table.add_column("Count")
        for ip, count in self.results["top_source_ips"].items():
            table.add_row(ip, str(count))
        self.console.print(table)

        self.console.print("[bold blue]Top Destination Domains:[/bold blue]")
        table = Table(show_header=True, header_style="bold magenta")
        table.add_column("Domain")
        table.add_column("Count")
        for domain, count in self.results["top_destination_domains"].items():
            table.add_row(domain, str(count))
        self.console.print(table)


def main():
    parser = argparse.ArgumentParser(description="Network Log Analyzer")
    parser.add_argument("--log_file", required=True, help="Path to the log file")
    parser.add_argument("--output_html", help="Path to output HTML report")
    parser.add_argument("--top_n", type=int, default=10, help="Number of top results to show")
    parser.add_argument("--filter", help="Filter condition")
    parser.add_argument("--start_time", help="Start time for filtering")
    parser.add_argument("--end_time", help="End time for filtering")
    parser.add_argument("--cli_report", action="store_true", help="Output CLI report")

    args = parser.parse_args()

    log_parser = LogParser(args.log_file)
    df = log_parser.parse_log()

    if df.empty:
        print("No valid log entries found.")
        return

    data_analyzer = DataAnalyzer(df)
    df = data_analyzer.clean_data()

    if args.start_time and args.end_time:
        start_time = datetime.strptime(args.start_time, "%Y/%m/%d %H:%M:%S")
        end_time = datetime.strptime(args.end_time, "%Y/%m/%d %H:%M:%S")
        df = df[(df["timestamp"] >= start_time) & (df["timestamp"] <= end_time)]

    analysis_results = data_analyzer.calculate_statistics(args.top_n)

    report_generator = ReportGenerator(analysis_results, args.log_file)

    if args.cli_report:
        report_generator.generate_cli_report()

    if args.output_html:
        report_generator.generate_html_report(args.output_html)


if __name__ == "__main__":
    main()