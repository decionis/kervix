# Shared by tests/target/secpol.sh and scripts/secpol-harvest.sh: the legitimate
# Kervix roles, exactly as deployed (agent, driver HMI, operator), as one
# target-side shell snippet. Run it with: $Q ssh "$KX_ROLES"
KX_TYPES="vsim_t vsim_run_t kervix_t kervix_run_t actuator_t actuator_run_t agentgw_t hmigw_t operator_t"
KX_DIGEST=sha256:0101010101010101010101010101010101010101010101010101010101010101
KX_ROLES="OP='on -T operator_t /system/bin/kervix/kxctl'; AG='on -T agentgw_t -u 400:400 /system/bin/kervix/kxctl'; HMI='on -T hmigw_t /system/bin/kervix/kxctl'
  \$AG propose --exec body.door.unlock door=front_left; \$AG propose --replay cabin.climate.set temp_dc=230
  \$AG propose --await --exec ota.ecu.flash ecu=brake image_digest=$KX_DIGEST > /tmp/e.out 2>&1 & p=\$!; sleep 1
  id=\$(\$HMI escalations | sed -n 's/^#\([0-9]*\) .*/\1/p' | head -1); \$HMI approve \$id; wait \$p; cat /tmp/e.out
  \$OP telemetry --watch 1; \$OP sim status; \$OP stats; rm -rf /tmp/dossier; \$OP dossier export /tmp/dossier"
kx_kervixd_pid() { $Q ssh 'pidin -p kervixd -F "%a" | tail -1 | tr -d " "'; }
