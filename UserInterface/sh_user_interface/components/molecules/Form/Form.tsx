import { FunctionComponent, HTMLAttributes, useState } from "react";
import Input, { InputProps } from "../../atoms/Input/Input";

interface FormProps extends HTMLAttributes<HTMLFormElement> {
  inputs: InputProps[];
  onSubmit: (data: any) => void;
}

const Form: FunctionComponent<FormProps> = ({ inputs, onSubmit, ...rest }) => {
  const [formData, setFormData] = useState({});

  const handleChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    setFormData({ ...formData, [e.target.name]: e.target.value });
  };

  const handleSubmit = async (e: React.FormEvent<HTMLFormElement>) => {
    e.preventDefault();
    await onSubmit(formData);
  };

  return (
    <form
      className="w-1/2 mx-auto flex flex-col border justify-center p-12 rounded-lg "
      {...rest}
      onSubmit={handleSubmit}
    >
      {inputs.map((input, index) => (
        <Input key={index} {...input} onChange={handleChange} />
      ))}

      <button
        type="submit"
        className="rounded-lg w-1/2 mt-8 border p-4 text-xl mx-auto"
      >
        Send
      </button>
    </form>
  );
};

export default Form;
