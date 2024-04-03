"use client";

import Form from "../../components/molecules/Form/Form";
import Cookies from "js-cookie";

const INPUTS = [
  {
    type: "text",
    placeholder: "example@mali.com",
    name: "email",
    label: "Email",
  },
  {
    type: "password",
    name: "password",
    label: "Password",
  },
];

export default function Home() {
  const handleSubmit = async (formData: any) => {
    try {
      const response = await fetch("/api/login", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify(formData),
      });
      const data = await response.json();
      const token = data.token;
      if (token) {
        Cookies.set("token", token);

        window.location.href = "/";
      }
    } catch (error) {
      console.error(error);
    }
  };

  return (
    <main className="flex min-h-screen flex-col items-center p-24">
      <h2 className="text-2xl font-semibold flex mb-10 w-1/2">LogIn</h2>
      <Form inputs={INPUTS} onSubmit={handleSubmit} />
    </main>
  );
}
