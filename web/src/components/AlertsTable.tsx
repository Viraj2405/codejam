import React, {
  useCallback,
  useEffect,
  useImperativeHandle,
  useMemo,
  useState,
} from "react";
import axios from "axios";
import {
  Box,
  Chip,
  CircularProgress,
  Paper,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  Typography,
} from "@mui/material";
import type { AlertRecord } from "../types";

const API_BASE_URL =
  process.env.REACT_APP_API_BASE_URL ?? "http://localhost:8081/api/v1";

interface AlertsTableProps {
  refreshInterval: number;
  onDataUpdate?: () => void;
}

export interface AlertsTableHandle {
  reload: () => void;
}

const severityColor: Record<string, "default" | "warning" | "error" | "info" | "success"> = {
  LOW: "default",
  MEDIUM: "info",
  HIGH: "warning",
  CRITICAL: "error",
};

const statusColor: Record<string, "default" | "warning" | "error" | "info" | "success"> = {
  OPEN: "error",
  INVESTIGATING: "warning",
  RESOLVED: "success",
  FALSE_POSITIVE: "default",
};

const AlertsTable = React.forwardRef<AlertsTableHandle, AlertsTableProps>(
  ({ refreshInterval, onDataUpdate }, ref) => {
    const [alerts, setAlerts] = useState<AlertRecord[]>([]);
    const [isLoading, setIsLoading] = useState<boolean>(false);
    const [error, setError] = useState<string | null>(null);

    const fetchAlerts = useCallback(async () => {
      setIsLoading(true);
      setError(null);
      try {
        const response = await axios.get(`${API_BASE_URL}/alerts`, {
          params: { limit: 50 },
        });
        const data = response.data.alerts ?? [];
        setAlerts(data);
        onDataUpdate?.();
      } catch (err) {
        console.error("Failed to fetch alerts", err);
        setError("Failed to fetch alerts. Check backend connectivity.");
      } finally {
        setIsLoading(false);
      }
    }, [onDataUpdate]);

    useImperativeHandle(
      ref,
      () => ({
        reload: fetchAlerts,
      }),
      [fetchAlerts]
    );

    useEffect(() => {
      fetchAlerts();
    }, [fetchAlerts]);

    useEffect(() => {
      if (refreshInterval <= 0) {
        return undefined;
      }
      const intervalId = window.setInterval(() => {
        fetchAlerts();
      }, refreshInterval);
      return () => {
        window.clearInterval(intervalId);
      };
    }, [fetchAlerts, refreshInterval]);

    const content = useMemo(() => {
      if (isLoading) {
        return (
          <Box display="flex" justifyContent="center" py={4}>
            <CircularProgress />
          </Box>
        );
      }

      if (error) {
        return (
          <Box py={4} textAlign="center">
            <Typography color="error">{error}</Typography>
          </Box>
        );
      }

      if (!alerts.length) {
        return (
          <Box py={4} textAlign="center">
            <Typography color="text.secondary">
              No alerts yet. Trigger detection rules to see results here.
            </Typography>
          </Box>
        );
      }

      return (
        <Table size="small">
          <TableHead>
            <TableRow>
              <TableCell>Alert Type</TableCell>
              <TableCell>User</TableCell>
              <TableCell>Severity</TableCell>
              <TableCell>Status</TableCell>
              <TableCell>Description</TableCell>
              <TableCell>Events</TableCell>
              <TableCell>Created</TableCell>
            </TableRow>
          </TableHead>
          <TableBody>
            {alerts.map((alert) => (
              <TableRow key={alert.id}>
                <TableCell>{alert.alert_type}</TableCell>
                <TableCell>{alert.user_id || "—"}</TableCell>
                <TableCell>
                  <Chip
                    label={alert.severity}
                    color={severityColor[alert.severity] ?? "default"}
                    size="small"
                  />
                </TableCell>
                <TableCell>
                  <Chip
                    label={alert.status}
                    color={statusColor[alert.status] ?? "default"}
                    size="small"
                  />
                </TableCell>
                <TableCell>{alert.description}</TableCell>
                <TableCell>{alert.event_refs?.length ?? 0}</TableCell>
                <TableCell>
                  {new Date(alert.created_at).toLocaleString()}
                </TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
      );
    }, [alerts, error, isLoading]);

    return (
      <Paper elevation={3}>
        <Box px={2} py={1.5} borderBottom="1px solid rgba(0,0,0,0.12)">
          <Typography variant="subtitle1">Latest Alerts</Typography>
        </Box>
        <TableContainer>{content}</TableContainer>
      </Paper>
    );
  }
);

export default AlertsTable;

