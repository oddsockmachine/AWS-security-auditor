from json import dump, load
from jinja2 import Template
from os.path import isfile


from risk_rules import risks
from models import *

from boto.ec2.connection import EC2Connection
import boto
# db.create_tables([Instance, SecGrp, FWRule])
# regions = ["us-west-1", "us-west-2", "us-east-1", "eu-west-1", "eu-central-1", "ap-northeast-1", "ap-southeast-1", "ap-southeast-2", "sa-east-1"] #"ap-northeast-2",
# for region in regions:
#     conn = boto.ec2.connect_to_region(region)
#     groups = conn.get_all_security_groups()
#     for group in groups:
#         _sg = SecGrp.create(name=str(group.name),
#                             description=str(group.description),
#                             region=str(group.region).replace("RegionInfo:",""),
#                             created=datetime.now().date())
#         for instance in group.instances():
#             _i = Instance.create(name=str(instance.tags.get("Name", "Unknown")),
#                                  state=str(instance.state),
#                                  description=str(instance.tags.get("Description", "No Description provided")),
#                                  region=str(instance.region).replace("RegionInfo:",""),
#                                  ip=str(instance.ip_address),
#                                  sec_grp=_sg,
#                                  created=datetime.now().date())
#         for rule in group.rules:
#             for grant in rule.grants:
#                 if "/" not in str(grant):
#                     continue
#                 _port = str(rule).split(":")[-1]
#                 _port = _port if "-1" not in _port else "all"
#                 _fwr = FWRule.create(port=_port,
#                                      cidr=str(grant),
#                                      description="Missing",
#                                      flag="",
#                                      sec_grp=_sg,
#                                      created=datetime.now().date())





# Template file for results tables
with open("template.html", "r") as template_file:
    html_template = "".join(template_file.readlines())
jtemplate = Template(html_template)

# Ignore anything that doesn't have any risks
for risk_type, risk_list in risks.items():
    if len(risk_list) == 0:
        del risks[risk_type]

# Convert risk names to link-suitable syntax
nav_links = [x.replace(" ", "_") for x in risks.keys()]
nav_links.append("index")  # Add index

# Write an index file with those links in - they're also added to the end of each results page
with open("./html/index.html", "w") as index_file:
    index_file.write("<html><ul><li>"+"</li><li>".join(['<a href="'+link+'.html">'+link+'</a>' for link in nav_links])+"</li></ul></html>")

# For each risk, fill the template with the results
for risk_type, risk_list in risks.items():
    title = risk_type
    headers = risk_list[0].keys()
    rows = [("<td>"+ "</td><td>".join(risk.values()) +"</td>") for risk in risk_list]
    content =  jtemplate.render(title=title, headers=headers, rows=rows, nav_links=nav_links)
    page_name = risk_type.replace(" ", "_")
    # Write the results page to html file
    with open("./html/"+page_name+".html", "w") as page_file:
        page_file.write(content)


# Hash the risks from both datasets so we can use set magic on them
def hash_risk(risk_type, risk_dict):
    keys_to_hash = [key for key in sorted(risk_dict.keys()) \
    if key not in ["instances", "num instances in sg"]]
    hash_str = "~".join([risk_type] + [risk_dict[key] for key in keys_to_hash])
    return hash_str

# if isfile("./data/previous_risks.json"):
# Get risks from previous scan so we can check for new diffs
with open("./data/previous_risks.json", "r") as prev_risk_file:
    prev_risks = load(prev_risk_file)

curr_risks = risks
curr_risk_set, prev_risk_set = set(), set()

# Create two sets of hashes
for risk_type, risk_dicts in curr_risks.items():
    for risk_dict in risk_dicts:
        curr_risk_set.add(hash_risk(risk_type, risk_dict))

for risk_type, risk_dicts in prev_risks.items():
    for risk_dict in risk_dicts:
        prev_risk_set.add(hash_risk(risk_type, risk_dict))

# Diff the two sets of data
new_risk_set = curr_risk_set - prev_risk_set
fixed_risk_set = prev_risk_set - curr_risk_set

new_risk_to_email, fixed_risk_to_email = [], []
for risk in new_risk_set:
    new_risk_to_email.append(risk.replace("~", ", "))
for risk in fixed_risk_set:
    fixed_risk_to_email.append(risk.replace("~", ", "))

# Stop here if there are no new risks. This both prevents empty emails being
# sent, and also bunches up any fixes into the next message (since the data file
# is not written)
if len(new_risk_to_email) == 0:
    exit()

notification_string = """Update from AWS security group audit tool.
-------------------------------------------------------

Found the following new security risks:
{}

-------------------------------------------------------

Also noticed that the following risks have been fixed:
{}

-------------------------------------------------------
""".format("\n".join(new_risk_to_email), "\n".join(fixed_risk_to_email))
print notification_string

import boto.ses
conn = boto.ses.connect_to_region('us-east-1')
# print conn.list_verified_email_addresses()
# print conn.send_email(
#         'david.walker@anaplan.com',
#         'Test AWS audit email',
#         notification_string,
#         ['david.walker@anaplan.com'])


print conn.get_send_quota()

# Write recently found risks to file so we
with open("./data/previous_risks.json", "w") as prev_risk_file:
    dump(curr_risks, prev_risk_file)





# todo:
# write automation script with cron - done
# get it working with both prod and nonprod - done, only one at a time
# use a new account for boto
# test on vagrant box with apache and cron - done
# find new/fixed risks
# notify by email
