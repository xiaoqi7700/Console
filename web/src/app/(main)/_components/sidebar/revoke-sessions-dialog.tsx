"use client";

import * as React from "react";

import { toast } from "sonner";

import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
} from "@/components/ui/alert-dialog";
import { api } from "@/lib/api";

// 审计 B1：吊销全部已登录会话（含当前设备）。管理面危险操作——后端要求
// confirm:true，前端在此给出二次确认弹窗；成功后清本地 token 跳登录页。
export function RevokeSessionsDialog({
  open,
  onOpenChange,
}: {
  readonly open: boolean;
  readonly onOpenChange: (open: boolean) => void;
}) {
  const [busy, setBusy] = React.useState(false);

  function confirm() {
    setBusy(true);
    api
      .revokeAllSessions()
      .then(() => {
        toast.success("已吊销全部会话，请重新登录");
        // 硬跳转拿全新登录态（token 已失效，保留它只会反复 401）
        window.location.href = "/login";
      })
      .catch((err) => toast.error(`吊销失败：${(err as Error).message}`))
      .finally(() => {
        setBusy(false);
        onOpenChange(false);
      });
  }

  return (
    <AlertDialog open={open} onOpenChange={onOpenChange}>
      <AlertDialogContent>
        <AlertDialogHeader>
          <AlertDialogTitle>吊销全部会话？</AlertDialogTitle>
          <AlertDialogDescription>
            所有已登录的设备（包括当前这台）都会被登出，需重新输入密码登录。怀疑 token 泄露但不想改密码时使用；
            修改密码同样会立即使全部旧会话失效。
          </AlertDialogDescription>
        </AlertDialogHeader>
        <AlertDialogFooter>
          <AlertDialogCancel disabled={busy}>取消</AlertDialogCancel>
          <AlertDialogAction
            disabled={busy}
            className="bg-destructive text-white hover:bg-destructive/90"
            onClick={(e) => {
              e.preventDefault();
              confirm();
            }}
          >
            {busy ? "吊销中…" : "全部吊销"}
          </AlertDialogAction>
        </AlertDialogFooter>
      </AlertDialogContent>
    </AlertDialog>
  );
}
