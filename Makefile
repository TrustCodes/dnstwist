build:
	docker build -t tc-hosts-scans .
tag:
	docker tag tc-hosts-scans:latest 263436898058.dkr.ecr.ap-southeast-2.amazonaws.com/tc-hosts-scans:latest
push:
	docker push 263436898058.dkr.ecr.ap-southeast-2.amazonaws.com/tc-hosts-scans:latest
