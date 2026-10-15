# In plain English: every command a workflow runs, as a fingerprint (a sha256 of the script text) with the name of the step it belongs to.
# A workflow may run ONLY scripts whose fingerprint is listed here, so a new step, or a changed one (a download piped into a shell, a
# command that swallows its own failure, a step that skips a check), turns tests/test_supply_chain_pins.py red until a pull request that
# someone reads adds its fingerprint on purpose. A listed fingerprint that no workflow runs any more also fails, so the list stays honest.
# The test prints the fingerprint of a new script when it fails. (The actions a workflow uses are checked separately: only the listed
# actions, each pinned to a commit.)
ALLOWED_RUN_STEPS = {
    'sha256:f75ca876d190f328f90f3baa3e4a2ed21eb0b808782e3ea6bfe5a7544840d25e': 'dependency-audit.yml / audit / Audit the libraries the service runs on',
    'sha256:14497e07edb2d4f2ae88c2001547228167a5c1878c1f79e2ef0a2c30e85afdcf': 'dependency-audit.yml / audit / Audit the libraries the tests use',
    'sha256:b9cb48df4de35746074ed09c3e9052681f224422c09881e367c09b91c7d90edc': "dependency-audit.yml / audit / Audit the scanner's own libraries",
    'sha256:7e13cc90ad41e41a3033b3dfebdcf15ef67a0e4ec4aff9c0e90958524861020b': 'dependency-audit.yml / audit / pip install --require-hashes --no-deps -r requirements-audit',
    'sha256:81fad3e739b66a73fbd524c22e5fa1947a46082c4119939107207760513f454c': 'image-scan.yml / scan / Build the pinned scanner',
    'sha256:6baa6714b030fadd85215450e28515757b99f24c12c8778b968f6078c3b5fd47': "image-scan.yml / scan / Build this service's image",
    'sha256:c936bac07c8f497d3bf21a3684b75821ab3bb79758c2321dcae76e677fdc6ff8': 'image-scan.yml / scan / Prove the scanner still catches a known flaw',
    'sha256:bc5fe7a08d62e6689e7634b28e9c05588dbdf12e336f8d418c64978b6df964b5': 'image-scan.yml / scan / Scan the image for fixable high and critical flaws',
    'sha256:04baa3a924f205ac80d085f8a498497cfa1149bc36b12b99f744f92e1e1f6b99': 'tests.yml / image-build / Build the image',
    'sha256:1538d8bdba521dbafca1999a67336d23c5f73b538492c3f6065f98372ce47665': 'tests.yml / image-build / Check /health and /ready',
    'sha256:ab8ad0568b9a1433d0295139a3c8cf9e21de3560583579d8ce17964b3a89bc94': 'tests.yml / image-build / Check it runs as user 1000',
    'sha256:b0b55b8df63dda6ce31cff0a183e49bd11d1514f839c0835fc58950c07fb9922': 'tests.yml / image-build / Check only the expected files are inside',
    'sha256:8c0c488759fa7fae9c7a7acc7b9d229838f4ca6005807dc906e9d7b3bb0be97c': 'tests.yml / image-build / Check the documentation pages are closed',
    'sha256:fd624205e9165ca3566a2a5d84254ef02a743ac287a259202e2bdf79a5878fdc': 'tests.yml / image-build / Clean up',
    'sha256:3cec903f7adb40701c3dc8d54eee4cd7e1b33d7128d0c9d983ecc0bc1770aaaf': 'tests.yml / image-build / Show the service log',
    'sha256:212d72cd6c96d1d5c19086b76df2c08107eb42da787ff1e4d93f2dc0e7dd2038': 'tests.yml / image-build / Start it with the network off',
    'sha256:ec70fac335e7e2c85fe99f425fc0c908ae72bc10d78d923cafb7ebbf5e1d1a60': 'tests.yml / image-build / Wait for the service to answer',
    'sha256:37c25f14966a4e36fd5322327bac87d161ec796148214abc4abf510d82605459': 'tests.yml / kubernetes-checks / Check the rendered Kubernetes files',
    'sha256:cb6a8481d2f0330f66a077eb698e352283be1e6f3a19dba1b1a8e58eb8472972': 'tests.yml / kubernetes-checks / Check the shell script',
    'sha256:baac7898930314a343b9b9f7169097c6a561e826e932e11f84a6547e81b3050d': 'tests.yml / kubernetes-checks / pip install --require-hashes -r requirements-dev.txt',
    'sha256:c8d40bd70442abfeb771761d066c972c576c3309196dabfe696e49c5bf078b72': 'tests.yml / tests / Run the tests',
}
