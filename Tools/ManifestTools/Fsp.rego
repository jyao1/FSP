# OPA playground: https://play.openpolicyagent.org/

package fsp

default FSPS_HASH_CHECK = false
FSPS_HASH_CHECK {
	input.reference.payload.directory.path_elements.file[0].hash[1] == input.evidence.FSPS
}

default FSPM_HASH_CHECK = false
FSPM_HASH_CHECK {
	input.reference.payload.directory.path_elements.file[1].hash[1] == input.evidence.FSPM
}

default FSPT_HASH_CHECK = false
FSPT_HASH_CHECK {
	input.reference.payload.directory.path_elements.file[2].hash[1] == input.evidence.FSPT
}

default error_code = 1
error_code = 0 { 
    FSPS_HASH_CHECK
    FSPM_HASH_CHECK
    FSPT_HASH_CHECK
}

# Output: error code, FSPS FSPM FSPT hash check
output := {
    "error_code": error_code,
    "FSPS": FSPS_HASH_CHECK,
    "FSPM": FSPM_HASH_CHECK,
    "FSPT": FSPT_HASH_CHECK
}
