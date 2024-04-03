import { FunctionComponent, InputHTMLAttributes } from "react";

export interface InputProps extends InputHTMLAttributes<HTMLInputElement> {
  type: string;
  placeholder?: string;
  name: string;
  label?: string;
}

const Input: FunctionComponent<InputProps> = ({
  type,
  placeholder,
  label,
  name,
  ...rest
}) => {
  return (
    <div className="flex flex-col mt-2 ">
      <label className="text-2xl" htmlFor={name}>
        {label}
      </label>
      <input
        {...rest}
        className="outline-none my-2 px-4 py-4 text-black"
        type={type}
        id={name}
        name={name}
        placeholder={placeholder}
      />
    </div>
  );
};

export default Input;
