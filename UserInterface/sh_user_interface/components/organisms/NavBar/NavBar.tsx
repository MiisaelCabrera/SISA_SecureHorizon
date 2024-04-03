"use client";
import Link from "next/link";
import { FunctionComponent, useEffect, useState } from "react";
import Cookies from "js-cookie";

import { useRouter } from "next/navigation";

interface NavBarProps {
  title: string;
}

const NavBar: FunctionComponent<NavBarProps> = ({ title }) => {
  const [token, setToken] = useState("");

  const router = useRouter();

  useEffect(() => {
    const token = Cookies.get("token") || "";
    setToken(token);
  }, [token]);

  const handleLogOut = () => {
    Cookies.remove("token");
    setToken("");
    router.push("/login");
    router.refresh();
  };

  return (
    <nav className="h-36 flex items-center justify-center font-semibold bg-slate-800 bg-opacity-75">
      <Link
        href={"/"}
        className="text-4xl hover:brightness-75  mx-auto transition-all ease-in-out duration-300"
      >
        {title}
      </Link>
      {token !== "" && (
        <button
          onClick={handleLogOut}
          className=" absolute border hover:brightness-75 transition-all duration-300 ease-in-out p-4 rounded-lg  right-12"
        >
          Log Out
        </button>
      )}
    </nav>
  );
};

export default NavBar;
