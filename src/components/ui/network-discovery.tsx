
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { WifiHigh, Bluetooth, EthernetPort, Usb, Network } from "lucide-react";
import { useState } from "react";

export interface DeviceDetailProps {
  id: string;
  name: string;
  ipAddress?: string;
  macAddress: string;
  connectionType: "ethernet" | "wifi" | "bluetooth" | "usb" | "other";
  status: "online" | "offline" | "unknown";
  lastSeen: string;
  signalStrength?: number;
  manufacturer?: string;
  os?: string;
}

export interface NetworkDiscoveryProps {
  discoveredDevices: {
    ethernet: number;
    wifi: number;
    bluetooth: number;
    usb: number;
    other: number;
  };
  onRefresh?: () => void;
  onExport?: () => void;
}

export const NetworkDiscovery = ({
  discoveredDevices,
  onRefresh,
  onExport
}: NetworkDiscoveryProps) => {
  return (
    <div>
      <div className="flex justify-between items-center mb-4">
        <h2 className="text-xl font-bold text-gray-900 dark:text-gray-100">Connected Devices</h2>
        <div className="flex items-center space-x-2">
          <Button 
            variant="outline" 
            size="sm"
            onClick={onRefresh}
          >
            Refresh Scan
          </Button>
          <Button 
            variant="outline" 
            size="sm"
            onClick={onExport}
          >
            Export Device List
          </Button>
        </div>
      </div>
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-5 gap-6 mb-8">
        <ConnectionCard 
          title="Ethernet" 
          icon={<EthernetPort className="h-5 w-5 text-blue-500" />}
          deviceCount={discoveredDevices.ethernet}
          status="Active"
          lastScan="2 minutes ago"
        />
        <ConnectionCard 
          title="WiFi" 
          icon={<WifiHigh className="h-5 w-5 text-green-500" />}
          deviceCount={discoveredDevices.wifi}
          status="Active"
          lastScan="5 minutes ago"
        />
        <ConnectionCard 
          title="Bluetooth" 
          icon={<Bluetooth className="h-5 w-5 text-indigo-500" />}
          deviceCount={discoveredDevices.bluetooth}
          status="Active" 
          lastScan="8 minutes ago"
        />
        <ConnectionCard 
          title="USB" 
          icon={<Usb className="h-5 w-5 text-purple-500" />}
          deviceCount={discoveredDevices.usb}
          status="Active"
          lastScan="10 minutes ago"
        />
        <ConnectionCard 
          title="Other" 
          icon={<Network className="h-5 w-5 text-yellow-500" />}
          deviceCount={discoveredDevices.other}
          status="Active"
          lastScan="15 minutes ago"
        />
      </div>
    </div>
  );
};

interface ConnectionCardProps {
  title: string;
  icon: React.ReactNode;
  deviceCount: number;
  status: string;
  lastScan: string;
}

const ConnectionCard = ({ title, icon, deviceCount, status, lastScan }: ConnectionCardProps) => (
  <Card className="border border-gray-200 dark:border-gray-700 shadow-sm hover:shadow-md transition-shadow">
    <CardHeader className="pb-2">
      <CardTitle className="text-lg flex items-center">
        {icon}
        <span className="ml-2">{title}</span>
      </CardTitle>
    </CardHeader>
    <CardContent>
      <div className="space-y-3">
        <div className="flex items-center justify-center">
          <span className="text-3xl font-bold text-gray-800 dark:text-gray-200">{deviceCount}</span>
          <span className="ml-2 text-sm text-gray-600 dark:text-gray-400">devices</span>
        </div>
        <div className="flex items-center justify-between">
          <span className="text-sm font-medium text-gray-700 dark:text-gray-300">Status:</span>
          <span className={`px-2 py-1 text-xs font-medium rounded ${
            status === "Active" ? "bg-green-100 text-green-800 dark:bg-green-900 dark:text-green-200" : 
            "bg-yellow-100 text-yellow-800 dark:bg-yellow-900 dark:text-yellow-200"
          }`}>
            {status}
          </span>
        </div>
        <div className="flex justify-between items-center text-sm">
          <span className="text-gray-600 dark:text-gray-400">Last scan:</span>
          <span className="font-medium text-gray-800 dark:text-gray-200">{lastScan}</span>
        </div>
        <Button variant="outline" className="w-full text-sm py-1" size="sm">
          View Details
        </Button>
      </div>
    </CardContent>
  </Card>
);
