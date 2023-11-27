# switch-l4s.p4 requires a specific version of p4s to compile it 
ALL_SRC  += switch-forward.p4 switch-int.p4
ALL_JSON += $(patsubst %.p4,%._, $(ALL_SRC))


compile: $(ALL_JSON)
	@echo "done"
	
%._: %.p4
	@echo "[COMPILE] $(notdir $<)"
	p4c --target bmv2 --arch v1model $<

clean:
	@rm -rf -- $(ALL_JSON)