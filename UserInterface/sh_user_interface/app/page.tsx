import DataContainer from "../components/organisms/DataContainer/DataContainer";

export default function Home() {
  return (
    <main className="flex min-h-screen flex-col items-center p-24">
      <h2 className="text-2xl font-semibold flex mb-10 w-10/12">Data flow</h2>
      <DataContainer />
    </main>
  );
}
