install:
	@npm install

node_modules:
	@npm install

checkdeps:
	 npm run check-deps

checkaudit:
	npm audit

test: node_modules
	npm run test
fasttest: node_modules
	npm run test-fast

lint: node_modules
	npm run lint

cover: node_modules
	npm run cover
fastcover: node_modules
	npm run cover-fast

check: checkdeps checkaudit docs types lint test cover

docs: node_modules
	npm run build-docs

types: node_modules
	node ./node_modules/jsdoc/jsdoc.js -c .jsdoc -t node_modules/tsd-jsdoc/dist -d ./
	tsc types.d.ts

.PHONY: all test clean docs browser
