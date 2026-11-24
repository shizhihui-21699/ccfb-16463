# Reference U-Boot environment/boot script with boot-count rollback.
# This is U-Boot hush command language, not Linux shell or C.
#
# U-Boot CONFIG_BOOTCOUNT_LIMIT owns bootcount initialization/increment:
# when upgrade_available != 0 it increments bootcount and, above bootlimit,
# runs altbootcmd instead of bootcmd. Do not increment bootcount manually here.
# Linux must run gw-boot-confirm after health checks to set bootcount=0 and
# upgrade_available=0.
#
# Replace mmc device/partition numbers and load addresses. In production, put
# this policy in the built-in/signed U-Boot environment or a signed FIT flow;
# an unsigned editable boot.scr is not a root of trust. Bootargs should live in
# the signed DTB chosen node or be forced by CONFIG_CMDLINE_FORCE.

setenv gw_addr 0x44000000
setenv bootlimit 3

if test -z "${gw_slot}"; then
	setenv gw_slot a
fi

# Install reusable rollback commands once into redundant environment. Bump
# gw_env_ver when changing these definitions in a fleet.
if test "${gw_env_ver}" != "1"; then
	setenv gw_env_ver 1

	setenv gw_swap_slot 'if test "${gw_slot}" = "b"; then setenv gw_slot a; else setenv gw_slot b; fi'
	setenv gw_clear_update 'setenv upgrade_available 0; setenv bootcount 0'

	setenv gw_boot_slot 'if test "${gw_slot}" = "b"; then load mmc 0:5 ${gw_addr} fitImage && bootm ${gw_addr}#conf-gw; else load mmc 0:3 ${gw_addr} fitImage && bootm ${gw_addr}#conf-gw; fi'
	setenv gw_boot_recovery 'load mmc 0:1 ${gw_addr} recovery.itb && bootm ${gw_addr}#conf-recovery'

	# Executed by U-Boot when bootcount exceeds bootlimit.
	setenv altbootcmd 'echo GW-BOOT: bootlimit exceeded, reverting; run gw_swap_slot; run gw_clear_update; saveenv; run gw_boot_slot; run gw_boot_recovery; reset'

	saveenv
fi

# Example signed arguments. Prefer a signed DTB per slot or fixed PARTLABELs.
# setenv bootargs "console=ttyAMA0,115200 root=PARTLABEL=root-${gw_slot} ro rootwait init=/sbin/gw-init module.sig_enforce=1 lockdown=integrity gw.mode=secure"

echo "GW-BOOT: trying slot ${gw_slot}"
run gw_boot_slot

# bootm returns only when loading/verification or Linux startup failed.
echo "GW-BOOT: slot ${gw_slot} failed; swapping to other slot"
run gw_swap_slot
saveenv
run gw_boot_slot

echo "GW-BOOT: both A/B slots failed; trying recovery"
run gw_boot_recovery
reset
