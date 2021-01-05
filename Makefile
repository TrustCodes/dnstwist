build:
	docker build -t 263436898058.dkr.ecr.ap-southeast-2.amazonaws.com/tc-hosts-scans:latest .
login:
	aws ecr get-login-password --region ap-southeast-2 | docker login --username AWS --password-stdin 263436898058.dkr.ecr.ap-southeast-2.amazonaws.com
push:
	docker push 263436898058.dkr.ecr.ap-southeast-2.amazonaws.com/tc-hosts-scans:latest
