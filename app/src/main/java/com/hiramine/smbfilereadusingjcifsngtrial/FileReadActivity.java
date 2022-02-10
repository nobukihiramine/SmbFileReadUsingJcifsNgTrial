package com.hiramine.smbfilereadusingjcifsngtrial;

import androidx.appcompat.app.AppCompatActivity;

import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.os.Message;
import android.text.method.ScrollingMovementMethod;
import android.util.Log;
import android.widget.TextView;
import android.widget.Toast;

public class FileReadActivity extends AppCompatActivity
{
	// 定数
	private static final String LOGTAG            = "FileReadActivity";
	public static final  String EXTRA_TARGET_PATH = "EXTRA_TARGET_PATH";
	public static final  String EXTRA_USERNAME    = "EXTRA_USERNAME";
	public static final  String EXTRA_PASSWORD    = "EXTRA_PASSWORD";

	// メンバー変数
	String m_strTargetPath;

	// Readingスレッドの結果取得
	private final Handler m_handlerReading = new Handler( Looper.getMainLooper() )
	{
		@Override
		public void handleMessage( Message message )
		{
			Log.d( LOGTAG, "End reading. : " + m_strTargetPath );
			switch( message.what )
			{
				case FileReader.RESULT_SUCCEEDED:
					String strText = (String)message.obj;
					TextView textview = findViewById( R.id.textview_main );
					textview.setText( strText );    // 表示更新
					return;
				case FileReader.RESULT_FAILED_UNKNOWN_HOST:
					Toast.makeText( FileReadActivity.this, "Unknown host. : " + m_strTargetPath, Toast.LENGTH_LONG ).show();
					finish();
					return;
				case FileReader.RESULT_FAILED_NO_ROUTE_TO_HOST:
					Toast.makeText( FileReadActivity.this, "No route to host. : " + m_strTargetPath, Toast.LENGTH_LONG ).show();
					finish();
					return;
				case FileReader.RESULT_FAILED_LOGON_FAILURE:
					Toast.makeText( FileReadActivity.this, "Logon failure. : " + m_strTargetPath, Toast.LENGTH_LONG ).show();
					finish();
					return;
				case FileReader.RESULT_FAILED_BAD_NETWORK_NAME:
					Toast.makeText( FileReadActivity.this, "Bad network name. : " + m_strTargetPath, Toast.LENGTH_LONG ).show();
					finish();
					return;
				case FileReader.RESULT_FAILED_NOT_FOUND:
					Toast.makeText( FileReadActivity.this, "Not found. : " + m_strTargetPath, Toast.LENGTH_LONG ).show();
					finish();
					return;
				case FileReader.RESULT_FAILED_FUNCTION_EXISTS:
					Toast.makeText( FileReadActivity.this, "Function exists() failed. : " + m_strTargetPath, Toast.LENGTH_LONG ).show();
					finish();
					return;
				default:
					Toast.makeText( FileReadActivity.this, "Failed with unknown cause. : ", Toast.LENGTH_LONG ).show();
					finish();
					//return;
			}
		}
	};

	@Override
	protected void onCreate( Bundle savedInstanceState )
	{
		super.onCreate( savedInstanceState );
		setContentView( R.layout.activity_file_read );

		// 呼び出し元からパラメータ取得
		Bundle extras        = getIntent().getExtras();
		m_strTargetPath = extras.getString( EXTRA_TARGET_PATH );
		String strUsername   = extras.getString( EXTRA_USERNAME );
		String strPassword   = extras.getString( EXTRA_PASSWORD );

		// スクロールできるように
		TextView textview = findViewById( R.id.textview_main );
		textview.setMovementMethod( ScrollingMovementMethod.getInstance() );
		textview.setHorizontallyScrolling( true );	// layoutファイルでの「scrollHorizontally」にはバグがあり、関数コール必要。

		// 別スレッドで読み込み開始
		Log.d( LOGTAG, "Start Reading. : " + m_strTargetPath );
		FileReader filereader = new FileReader();
		filereader.startReading( m_handlerReading,
								 m_strTargetPath,
								 strUsername,
								 strPassword );
	}
}