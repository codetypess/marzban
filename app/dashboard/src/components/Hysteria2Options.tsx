import { Button, FormControl, FormLabel, HStack, Input, Select, Switch, Text, VStack } from "@chakra-ui/react";
import { Proxy, ProxySettings } from "contexts/ClashContext";
import { useFormContext } from "react-hook-form";
import { useTranslation } from "react-i18next";

type Options = NonNullable<ProxySettings["hysteria2"]>;

export const Hysteria2Options = ({ disabled, defaults }: { disabled: boolean; defaults?: Options }) => {
  const { watch, setValue } = useFormContext<Proxy>();
  const { t } = useTranslation();
  const overrides = watch("settings.hysteria2") || {};
  const options = {
    sni: "", obfs: "", obfs_password: "", allow_insecure: false,
    ...defaults, ...overrides,
  };
  const update = (value: Options) => setValue("settings.hysteria2", { ...overrides, ...value }, { shouldDirty: true });
  const optionalNumber = (value: string) => value === "" ? null : Number(value);
  return (
    <VStack w="full">
      <Text fontSize="sm" color="gray.500">{t("clash.proxy.inheritInfo")}</Text>
      <Button size="sm" variant="outline" disabled={disabled || !Object.keys(overrides).length}
        onClick={() => setValue("settings.hysteria2", {}, { shouldDirty: true })}>
        {t("clash.proxy.restoreInheritance")}
      </Button>
      <FormControl>
        <FormLabel>SNI</FormLabel>
        <Input size="sm" borderRadius="6px" disabled={disabled}
          value={options.sni} onChange={(e) => update({ sni: e.target.value })} />
      </FormControl>
      <FormControl>
        <FormLabel>{t("clash.proxy.obfs")}</FormLabel>
        <Select size="sm" disabled={disabled} value={options.obfs}
          onChange={(e) => update({ obfs: e.target.value as Options["obfs"] })}>
          <option value="">{t("clash.proxy.obfsNone")}</option>
          <option value="salamander">Salamander</option>
        </Select>
      </FormControl>
      {options.obfs === "salamander" && (
        <FormControl isRequired>
          <FormLabel>{t("clash.proxy.obfsPassword")}</FormLabel>
          <Input size="sm" borderRadius="6px" disabled={disabled} required
            value={options.obfs_password} onChange={(e) => update({ obfs_password: e.target.value })} />
        </FormControl>
      )}
      <HStack w="full">
        <FormControl>
          <FormLabel>{t("clash.proxy.upMbps")}</FormLabel>
          <Input size="sm" type="number" min={1} step={1} disabled={disabled}
            value={options.up_mbps ?? ""} onChange={(e) => update({ up_mbps: optionalNumber(e.target.value) })} />
        </FormControl>
        <FormControl>
          <FormLabel>{t("clash.proxy.downMbps")}</FormLabel>
          <Input size="sm" type="number" min={1} step={1} disabled={disabled}
            value={options.down_mbps ?? ""} onChange={(e) => update({ down_mbps: optionalNumber(e.target.value) })} />
        </FormControl>
      </HStack>
      <FormControl display="flex" alignItems="center">
        <FormLabel mb="0">{t("clash.proxy.allowInsecure")}</FormLabel>
        <Switch colorScheme="primary" disabled={disabled}
          isChecked={options.allow_insecure} onChange={(e) => update({ allow_insecure: e.target.checked })} />
      </FormControl>
    </VStack>
  );
};
