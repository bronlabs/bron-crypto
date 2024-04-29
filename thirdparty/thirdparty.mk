BORINGSSL_SUBMODULE=$(CURDIR)/thirdparty/boringssl
BORINGSSL_BUILD=${BORINGSSL_SUBMODULE}/build

.PHONY: deps-boring
deps-boring:
	@{ command -v git >/dev/null 2>&1 && git rev-parse --is-inside-work-tree >/dev/null 2>&1 && git submodule update --init ${BORINGSSL_SUBMODULE} && echo "boring-ssl submodule is updated."; } || echo "git not present. continuing without updating boring-ssl submodule."
	$(MAKE) build-boring


# might not work on windows
.PHONY: build-boring
build-boring:
	cmake $(CURDIR)/thirdparty/boringssl -DCMAKE_BUILD_TYPE=Release -DOPENSSL_SMALL=1 -GNinja -B ${BORINGSSL_BUILD}
	ninja -C ${BORINGSSL_BUILD} -j7 crypto


