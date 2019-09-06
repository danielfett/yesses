import os
import time
import re
import slack
import prettytable
import io

class Slack:
    def __init__(self, channels, token=None):
        self.channels = channels
        
        if not token:
            try:
                token = os.environ['YESSES_SLACK_TOKEN']
            except KeyError:
                raise Exception("Please provide either the 'token' keyword to the Slack output or provide the token in the environment variable YESSES_SLACK_TOKEN.")
                
        self.client = slack.WebClient(token=token)

    def run(self, alertslist):
        avars = alertslist.get_vars()

        if avars['max_severity'] is not None:
            table = prettytable.PrettyTable(("Severity", "# Alerts", "# Findings"))
            table.align["Severity"] = "l"
            table.align["# Alerts"] = "r"
            table.align["# Findings"] = "r"

            for row in avars['summary']:
                table.add_row((row['severity'].name, row['alerts'], row['findings']))
            findings_summary = f"\nFindings:\n```\n{table}\n```"
        else:
            findings_summary = "No findings."
            
        message = f"""*yesses report*:
Run started on {avars['started']}. {findings_summary}
"""
        for channel in self.channels:
            response = self.client.chat_postMessage(
                channel=channel,
                text=message)
            #ts = response['ts']
            #self.client.files_upload(
            #    channels=[channel],
            #    filename='sample.txt',
            #    title='sampletitle',
            #    initial_comment='sampletext',
            #    file=io.BytesIO(bytes(message, 'ascii')),
            #    thread_ts=ts,
            #)
