# switch-l4s.p4 requires a specific version of p4s to compile it 
ALL_SRC  += switch-flow.p4 switch-forward.p4 switch-int.p4
ALL_JSON += $(patsubst %.p4,%.json, $(ALL_SRC))


compile: $(ALL_JSON)
	@echo "done"
	
%.json: %.p4
	@echo "[COMPILE] $(notdir $<)"
	p4c --target bmv2 --arch v1model $<

compile-flow:
	p4c --target bmv2 --arch v1model switch-flow.p4

clean:
	@rm -rf -- $(ALL_JSON)