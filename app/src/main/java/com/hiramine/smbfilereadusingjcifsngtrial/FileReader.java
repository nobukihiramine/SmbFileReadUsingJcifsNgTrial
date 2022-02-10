package com.hiramine.smbfilereadusingjcifsngtrial;

import android.os.Handler;
import android.os.Message;
import android.util.Log;

import java.io.IOException;
import java.io.InputStream;
import java.net.NoRouteToHostException;
import java.net.UnknownHostException;
import java.util.Properties;

import jcifs.CIFSContext;
import jcifs.CIFSException;
import jcifs.config.PropertyConfiguration;
import jcifs.context.BaseContext;
import jcifs.smb.NtStatus;
import jcifs.smb.NtlmPasswordAuthenticator;
import jcifs.smb.SmbException;
import jcifs.smb.SmbFile;
import jcifs.util.transport.TransportException;

public class FileReader
{
	// 定数
	private static final String LOGTAG = "FileReader";

	public static final int RESULT_SUCCEEDED               = 0;
	public static final int RESULT_FAILED_UNKNOWN_HOST     = 1;
	public static final int RESULT_FAILED_NO_ROUTE_TO_HOST = 2;
	public static final int RESULT_FAILED_LOGON_FAILURE    = 3;
	public static final int RESULT_FAILED_BAD_NETWORK_NAME = 4;
	public static final int RESULT_FAILED_NOT_FOUND        = 5;
	public static final int RESULT_FAILED_FUNCTION_EXISTS  = 11;
	public static final int RESULT_FAILED_UNKNOWN          = 99;

	// スレッドの作成と開始
	public void startReading( Handler handler,
							  String strTargetPath,
							  String strUsername,
							  String strPassword )
	{
		Thread thread = new Thread( () -> threadfuncRead( handler,
														  strTargetPath,
														  strUsername,
														  strPassword ) );
		thread.start();
	}

	// スレッド関数
	private void threadfuncRead( Handler handler,
								 String strTargetPath,
								 String strUsername,
								 String strPassword )
	{
		Log.d( LOGTAG, "Reading thread started." );

		// 呼び出し元スレッドに返却する用のメッセージ変数の取得
		Message message = Message.obtain( handler );

		try
		{
			// CIFSContextの作成
			CIFSContext cifscontext = createCIFSContext( strUsername, strPassword );

			// SmbFileオブジェクト作成
			SmbFile smbfile = new SmbFile( strTargetPath, cifscontext );
			boolean bIsExists;
			try
			{
				bIsExists = smbfile.exists();
			}
			catch( SmbException e )
			{
				if( NtStatus.NT_STATUS_UNSUCCESSFUL == e.getNtStatus()
					&& e.getCause() instanceof UnknownHostException )
				{    // 不明なホスト
					message.what = RESULT_FAILED_UNKNOWN_HOST;
					message.obj = null;
					Log.w( LOGTAG, "Reading thread end. : Unknown host." );
					return;    // ※注）関数を抜ける前にfinallyの処理が実行される。
				}
				else if( NtStatus.NT_STATUS_UNSUCCESSFUL == e.getNtStatus()
						 && e.getCause() instanceof TransportException
						 && e.getCause().getCause() instanceof NoRouteToHostException )
				{    // ホストへのルートがない
					message.what = RESULT_FAILED_NO_ROUTE_TO_HOST;
					message.obj = null;
					Log.w( LOGTAG, "Reading thread end. : No route to host." );
					return;    // ※注）関数を抜ける前にfinallyの処理が実行される。
				}
				else if( NtStatus.NT_STATUS_LOGON_FAILURE == e.getNtStatus() )
				{    // SmbFile#exists()の結果「Logon failure」
					message.what = RESULT_FAILED_LOGON_FAILURE;
					message.obj = null;
					Log.w( LOGTAG, "Reading thread end. : Logon failure." );
					return;    // ※注）関数を抜ける前にfinallyの処理が実行される。
				}
				else if( NtStatus.NT_STATUS_BAD_NETWORK_NAME == e.getNtStatus() )
				{    // 不明なShare名
					message.what = RESULT_FAILED_BAD_NETWORK_NAME;
					message.obj = null;
					Log.w( LOGTAG, "Reading thread end. : Bad network name." );
					return;    // ※注）関数を抜ける前にfinallyの処理が実行される。
				}
				else
				{    // SmbFile#exists()の結果、原因不明で失敗
					message.what = RESULT_FAILED_FUNCTION_EXISTS;
					message.obj = null;
					Log.e( LOGTAG, "Reading thread end. : Function exists() failed." );
					return;    // ※注）関数を抜ける前にfinallyの処理が実行される。
				}
			}
			if( !bIsExists )
			{    // パスが存在しない
				message.what = RESULT_FAILED_NOT_FOUND;
				message.obj = null;
				Log.w( LOGTAG, "Reading thread end. : Not found." );
				return;    // ※注）関数を抜ける前にfinallyの処理が実行される。
			}

			// 読み込み
			InputStream inputstream = smbfile.getInputStream();
			long        lLength     = smbfile.getContentLengthLong();
			byte[]      buffer      = new byte[(int)lLength];
			int         bytesRead   = inputstream.read( buffer );
			assert bytesRead == lLength;
			String strText = new String( buffer );    // byte配列を文字列に変換

			// 成功
			message.what = RESULT_SUCCEEDED;
			message.obj = strText;
			Log.d( LOGTAG, "Reading thread end. : Succeeded." );
		}
		catch( IOException e )
		{	// その他の失敗
			message.what = RESULT_FAILED_UNKNOWN;
			message.obj = e.getMessage();
			Log.e( LOGTAG, "Reading thread end. : Failed with unknown cause." );
		}
		finally
		{
			// 呼び出し元スレッドにメッセージ返却
			handler.sendMessage( message );
		}
	}

	// CIFSContextの作成
	public static CIFSContext createCIFSContext( String strUsername,
												 String strPassword ) throws CIFSException
	{
		// SmbFileオブジェクト作成
		Properties prop = new Properties();
		prop.setProperty( "jcifs.smb.client.minVersion", "SMB202" );    // SMB1, SMB202
		prop.setProperty( "jcifs.smb.client.maxVersion", "SMB311" );    // SMB1, SMB311
		PropertyConfiguration     propconfig  = new PropertyConfiguration( prop );
		BaseContext               basecontext = new BaseContext( propconfig );
		NtlmPasswordAuthenticator authenticator;
		if( strUsername.isEmpty() )
		{    // ユーザー名が空の場合は、アノニマスで作成
			authenticator = new NtlmPasswordAuthenticator();
		}
		else
		{    // ユーザー名とパスワードを指定して作成
			authenticator = new NtlmPasswordAuthenticator( strUsername, strPassword );
		}
		return basecontext.withCredentials( authenticator );
	}
}

