import React, {
  ButtonHTMLAttributes,
  FunctionComponent,
  ReactNode,
} from "react";

interface ToggleButtonProps extends ButtonHTMLAttributes<HTMLButtonElement> {
  isActive: boolean;
  icons: { show: ReactNode; hide: ReactNode };
}

const ToggleButton: FunctionComponent<ToggleButtonProps> = ({
  isActive,
  icons,
  ...rest
}) => {
  return <button {...rest}>{isActive ? icons.show : icons.hide}</button>;
};

export default ToggleButton;
