from models import *

# Queries for different types of risks we want to know about:
risks = {}

# SecGrps with no running instances
risks["SecGrps with no running instances"] = []
sgs = SecGrp.select()
for sg in sgs:
    if len([i.name for i in sg.instances]) == 0:
        risk = {"sec_grp name": sg.name,
                "region": sg.region}
        risks["SecGrps with no running instances"].append(risk)

# SecGrps still using default name ("launch-wizard")
risks["SecGrps still using default name"] = []
sgs = SecGrp.select()
for sg in sgs:
    if "launch-wizard" in sg.name:
        risk = {"sec_grp name": sg.name,
                "region": sg.region,
                "num instances in sg": str(len(sg.instances)),
                "instances": ", ".join([i.name for i in sg.instances])}
        risks["SecGrps still using default name"].append(risk)

# fwrs with 0.0.0.0/0 && 22
risks["SSH ports open to the world"] = []
fwrs = FWRule.select().where(FWRule.cidr == '0.0.0.0/0').where(FWRule.port == "tcp(22-22)")
for fwr in fwrs:
    sg = fwr.sec_grp
    risk = {"sec_grp name": sg.name,
            "region": sg.region,
            "num instances in sg": str(len(sg.instances)),
            "instances": ", ".join([i.name for i in sg.instances])}
    risks["SSH ports open to the world"].append(risk)

# fwrs with 0.0.0.0/0 && all
risks["All ports open to the world"] = []
fwrs = FWRule.select().where(FWRule.cidr == '0.0.0.0/0').where(FWRule.port == "all")
for fwr in fwrs:
    sg = fwr.sec_grp
    risk = {"sec_grp name": sg.name,
            "region": sg.region,
            "num instances in sg": str(len(sg.instances)),
            "instances": ", ".join([i.name for i in sg.instances])}
    risks["All ports open to the world"].append(risk)

# fwrs with 0.0.0.0/0
risks["Any ports open to the world"] = []
fwrs = FWRule.select().where(FWRule.cidr == '0.0.0.0/0')
for fwr in fwrs:
    port = fwr.port
    sg = fwr.sec_grp
    risk = {"sec_grp name": sg.name,
            "region": sg.region,
            "port open": port,
            "num instances in sg": str(len(sg.instances)),
            "instances": ", ".join([i.name for i in sg.instances])}
    risks["Any ports open to the world"].append(risk)

# fwrs with 0.0.0.0/0 && 80
risks["HTTP port open to the world"] = []
fwrs = FWRule.select().where(FWRule.cidr == '0.0.0.0/0').where(FWRule.port == "tcp(80-80)")
for fwr in fwrs:
    sg = fwr.sec_grp
    risk = {"sec_grp name": sg.name,
            "region": sg.region,
            "num instances in sg": str(len(sg.instances)),
            "instances": ", ".join([i.name for i in sg.instances])}
    risks["HTTP port open to the world"].append(risk)

# fwrs with 0.0.0.0/0 && 3389
risks["open rdp"] = []
fwrs = FWRule.select().where(FWRule.cidr == '0.0.0.0/0').where(FWRule.port == "tcp(3389-3389)")
for fwr in fwrs:
    sg = fwr.sec_grp
    risk = {"sec_grp name": sg.name,
            "region": sg.region,
            "num instances in sg": str(len(sg.instances)),
            "instances": ", ".join([i.name for i in sg.instances])}
    risks["HTTP port open to the world"].append(risk)


# Instances without descriptions
risks["Instances without descriptions"] = []
instances = Instance.select().where(Instance.description == 'No Description provided')
for i in instances:
    risk = {"instance name": i.name,
            "region": i.region,
            "IP": i.ip,
            "sec_grp": i.sec_grp.name}
    risks["Instances without descriptions"].append(risk)

# Instances without names
risks["Instances without names"] = []
instances = Instance.select().where(Instance.name == 'Unknown')
for i in instances:
    risk = {"region": i.region,
            "IP": i.ip,
            "sec_grp": i.sec_grp.name}
    risks["Instances without names"].append(risk)
