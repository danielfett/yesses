import os
import time
import re
import slack
import prettytable
import io
import logging

log = logging.getLogger('output/slack')

class Slack:
    def __init__(self, channels, token=None):
        self.channels = channels
        
        if not token:
            try:
                token = os.environ['YESSES_SLACK_TOKEN']
            except KeyError:
                raise Exception("Please provide either the 'token' keyword to the Slack output or provide the token in the environment variable YESSES_SLACK_TOKEN.")
                
        self.client = slack.WebClient(token=token)

    def run(self, alertslist, steps, time):
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
Run started on {avars['started']}; took {time}s. {findings_summary}
"""
        for channel in self.channels:
            response = self.client.chat_postMessage(
                channel=channel,
                text=message)
            log.info(f"Notification sent on channel {channel}")
