# ReadyHai conftest policy pack (runs via plugins/official/conftest after
# `scripts/fetch-feeds.sh rego`). Modern rego syntax (v1: if/contains required).
package readyhai.k8s

deny contains msg if {
	input.kind in {"Pod", "Deployment", "StatefulSet", "DaemonSet", "Job", "CronJob"}
	c := input.spec.template.spec.containers[_]
	c.securityContext.privileged == true
	msg := sprintf("container %q runs privileged (readyhai.k8s.privileged)", [c.name])
}

deny contains msg if {
	input.kind in {"Pod", "Deployment", "StatefulSet", "DaemonSet", "Job", "CronJob"}
	c := input.spec.template.spec.containers[_]
	endswith(c.image, ":latest")
	msg := sprintf("image %q uses mutable :latest tag (readyhai.k8s.latest-tag)", [c.image])
}

deny contains msg if {
	input.kind in {"Pod", "Deployment", "DaemonSet", "StatefulSet", "Job"}
	c := input.spec.containers[_]
	c.securityContext.privileged == true
	msg := sprintf("container %q runs privileged (readyhai.k8s.privileged)", [c.name])
}

deny contains msg if {
	input.kind in {"Pod", "Deployment", "DaemonSet", "StatefulSet", "Job"}
	v := input.spec.volumes[_]
	v.hostPath.path
	msg := sprintf("hostPath volume %q mounts %s (readyhai.k8s.hostpath)", [v.name, v.hostPath.path])
}
