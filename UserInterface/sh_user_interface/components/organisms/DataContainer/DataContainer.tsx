"use client";
import { ChangeEvent, FunctionComponent, useEffect, useState } from "react";
import ListIcon from "../../atoms/icons/List";
import GraphIcon from "../../atoms/icons/Graph";
import GraphContainer from "../../molecules/GraphContainer/GraphContainer";
import ToggleButton from "@/components/atoms/ToggleButton/ToggleButton";
import TableContainer from "@/components/molecules/TableContainer/TableContainer";

interface TrafficData {
  generated: Date;
  appName: string;
  totalSourceBytes: number;
  totalDestinationBytes: number;
  totalDestinationPackets: number;
  totalSourcePackets: number;
  sourcePayloadAsBase64: string;
  sourcePayloadAsUTF: string;
  destinationPayloadAsBase64: string;
  destinationPayloadAsUTF: string;
  sourceTCPFlagsDescription: string;
  destinationTCPFlagsDescription: string;
  source: string;
  protocolName: string;
  sourcePort: number;
  destination: string;
  destinationPort: number;
  startDateTime: string;
  stopDateTime: string;
  Label: string;
}

const HEADERS = [
  { head: "Source", id: "source" },
  { head: "Protocol", id: "protocolName" },
  { head: "Application Name", id: "appName" },
  { head: "Packets sent", id: "totalDestinationPackets" },
  { head: "Packets received", id: "totalSourcePackets" },
  { head: "Destination", id: "destination" },
];

const BUTTON_ICONS = {
  show: <ListIcon className="h-6 w-6" />,
  hide: <GraphIcon className="h-6 w-6" />,
};

const DataContainer: FunctionComponent = () => {
  const [trafficData, setTrafficData] = useState([] as TrafficData[]);
  const [interval, setInterval] = useState(60000); // 1 minute [ms]
  const [isGraphView, setIsGraphView] = useState(true);

  const fetchData = async () => {
    try {
      const response = await fetch("/csvjson.json"); // Ruta relativa al archivo JSON
      const data = await response.json();
      setTrafficData(data.data);
    } catch (error) {
      console.error("Error fetching data:", error);
    }
  };

  useEffect(() => {
    console.log(isGraphView);
  }, [isGraphView]);

  useEffect(() => {
    setTimeout(() => {
      fetchData();
    }, interval);
  }, [trafficData]);

  useEffect(() => {
    fetchData();
  }, []);

  const handleIntervalChange = (event: ChangeEvent<HTMLSelectElement>) => {
    setInterval(parseInt(event.target.value));
  };

  return (
    <div className=" border-2 flex flex-col w-10/12 rounded-lg">
      <div className="flex p-2 border-b">
        <ToggleButton
          className="border w-12 h-12 flex items-center justify-center rounded-lg bg-black"
          isActive={isGraphView}
          onClick={() => setIsGraphView(!isGraphView)}
          icons={BUTTON_ICONS}
        ></ToggleButton>
        <span className="my-auto mr-2 mx-auto items-center">
          Updating every:
        </span>
        <select
          name="interval"
          id="interval"
          onChange={handleIntervalChange}
          className="w-32  h-12 px-2 bg-black outline-none my-auto border rounded-lg  mx-2"
          defaultValue={interval.toString()}
        >
          <option value="30000">30 Seconds</option>
          <option value="60000">1 Minute</option>
          <option value="3600000">1 Hour</option>
          <option value="86400000">1 Day</option>
        </select>
      </div>
      <GraphContainer
        trafficData={trafficData}
        className={isGraphView ? "flex" : "hidden"}
      />
      <TableContainer
        trafficData={trafficData}
        className={isGraphView ? "hidden" : "block"}
        headers={HEADERS}
      />
    </div>
  );
};

export default DataContainer;
