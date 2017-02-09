# import boto.ses
#
#
# notification_string = """Update from AWS security group audit tool.
# -------------------------------------------------------
#
# Found the following new security risks:
# {}
#
# -------------------------------------------------------
#
# Also noticed that the following risks have been fixed:
# {}
#
# -------------------------------------------------------
# """.format("\n".join(new_risk_to_email), "\n".join(fixed_risk_to_email))
# print notification_string
#
# conn = boto.ses.connect_to_region('us-east-1')
#
# # Get email recipients from file. Should be list separated by newlines
# with open("email_recipients.txt", "r") as email_file:
#     recipients = email_file.readlines()
# print recipients
# # print conn.list_verified_email_addresses()
# # print conn.send_email(
# #         'david.walker@anaplan.com',
# #         'Test AWS audit email',
# #         notification_string,
# #         recipients)
#
#
# print conn.get_send_quota()
